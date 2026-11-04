using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    // Writers hold BrovVulkDevice.Lock. Shaders read the tables without it.
    internal sealed unsafe class BrovVulkAddressSpace : IDisposable
    {
        public const ulong Base = 0x0000100000000000;
        public const int LeafShift = 30;
        public const int GranuleShift = 16;
        public const ulong SlotMask = (1ul << (LeafShift - GranuleShift)) - 1;
        public const int SinkBytes = 1 << GranuleShift;
        private const ulong Granule = 1ul << GranuleShift;
        private const int SlotsPerLeaf = 1 << (LeafShift - GranuleShift);
        private const int RecordBytes = 24;

        private readonly ulong* _top;
        private readonly ulong* _zeroLeaf;
        private readonly ulong* _zeroRecord;
        private readonly byte* _sink;
        private readonly List<(ulong Base, ulong Span)> _free = new List<(ulong, ulong)>();
        private readonly HashSet<IntPtr> _records = new HashSet<IntPtr>();
        private ulong _next = Base;
        private bool _disposed;

        private BrovVulkAddressSpace(ulong* top, int topCount, ulong* zeroLeaf, ulong* zeroRecord, byte* sink)
        {
            _top = top;
            TopCount = (ulong)topCount;
            _zeroLeaf = zeroLeaf;
            _zeroRecord = zeroRecord;
            _sink = sink;
            new Span<byte>(_sink, SinkBytes).Clear();
            _zeroRecord[0] = 0;
            _zeroRecord[1] = (ulong)_sink;
            _zeroRecord[2] = 0;
            new Span<ulong>(_zeroLeaf, SlotsPerLeaf).Fill((ulong)_zeroRecord);
            new Span<ulong>(_top, topCount).Fill((ulong)_zeroLeaf);
        }

        public static BrovVulkAddressSpace? TryCreate()
        {
            int topCount = MemoryBudget.VulkanAddressLeaves;
            byte* sink = null;
            ulong* zeroRecord = null, zeroLeaf = null, top = null;
            try
            {
                sink = (byte*)NativeMemory.AlignedAlloc(SinkBytes, SinkBytes);
                zeroRecord = (ulong*)NativeMemory.AlignedAlloc(64, 64);
                zeroLeaf = (ulong*)NativeMemory.AlignedAlloc((nuint)SlotsPerLeaf * 8, 64);
                top = (ulong*)NativeMemory.AlignedAlloc((nuint)topCount * 8, 64);
            }
            catch (OutOfMemoryException)
            {
                NativeMemory.AlignedFree(zeroLeaf);
                NativeMemory.AlignedFree(zeroRecord);
                NativeMemory.AlignedFree(sink);
                return null;
            }
            return new BrovVulkAddressSpace(top, topCount, zeroLeaf, zeroRecord, sink);
        }

        public ulong TopAddress => (ulong)_top;

        public ulong TopCount { get; }

        public ulong ZeroLeafAddress => (ulong)_zeroLeaf;

        public ulong SinkAddress => (ulong)_sink;

        public bool TryRegister(ulong size, ulong hostBase, out ulong guest, out ulong span, out IntPtr record)
        {
            guest = span = 0;
            record = IntPtr.Zero;
            if (size == 0 || size > (TopCount << LeafShift) || hostBase == 0 || (hostBase & 7) != 0)
                return false;

            span = BinaryEmulator.AlignUp(size, Granule) + Granule;
            if (!TryTakeRange(span, out guest))
                return false;

            ulong* fields;
            try
            {
                for (ulong top = (guest - Base) >> LeafShift; top <= (guest + span - Granule - 1 - Base) >> LeafShift; top++)
                    EnsureLeaf(top);
                fields = (ulong*)NativeMemory.AlignedAlloc(RecordBytes, 64);
            }
            catch (OutOfMemoryException)
            {
                Return(guest, span);
                return false;
            }

            fields[0] = guest;
            fields[1] = hostBase;
            fields[2] = size;
            record = (IntPtr)fields;
            _records.Add(record);
            Publish(guest, span, (ulong)fields);
            return true;
        }

        public void Clear(ulong guest, ulong span) => Publish(guest, span, (ulong)_zeroRecord);

        private void Publish(ulong guest, ulong span, ulong record)
        {
            for (ulong at = guest; at < guest + span - Granule; at += Granule)
            {
                ulong* leaf = (ulong*)_top[(at - Base) >> LeafShift];
                Volatile.Write(ref leaf[((at - Base) >> GranuleShift) & SlotMask], record);
            }
        }

        // Free records after retirement. Shaders can hold leaf addresses until teardown.
        public void Free(ulong guest, ulong span, IntPtr record)
        {
            if (_records.Remove(record))
                NativeMemory.AlignedFree((void*)record);
            Return(guest, span);
        }

        private void Return(ulong guest, ulong span)
        {
            int at = 0;
            while (at < _free.Count && _free[at].Base < guest)
                at++;
            _free.Insert(at, (guest, span));
            if (at + 1 < _free.Count && _free[at].Base + _free[at].Span == _free[at + 1].Base)
            {
                _free[at] = (_free[at].Base, _free[at].Span + _free[at + 1].Span);
                _free.RemoveAt(at + 1);
            }
            if (at > 0 && _free[at - 1].Base + _free[at - 1].Span == _free[at].Base)
            {
                _free[at - 1] = (_free[at - 1].Base, _free[at - 1].Span + _free[at].Span);
                _free.RemoveAt(at);
                at--;
            }
            if (_free[at].Base + _free[at].Span == _next)
            {
                _next = _free[at].Base;
                _free.RemoveAt(at);
            }
        }

        private bool TryTakeRange(ulong span, out ulong guest)
        {
            for (int i = 0; i < _free.Count; i++)
            {
                (ulong start, ulong length) = _free[i];
                if (length < span)
                    continue;
                guest = start;
                if (length == span)
                    _free.RemoveAt(i);
                else
                    _free[i] = (start + span, length - span);
                return true;
            }

            guest = _next;
            if (span > Base + (TopCount << LeafShift) - _next)
                return false;
            _next += span;
            return true;
        }

        private void EnsureLeaf(ulong top)
        {
            if (_top[top] != (ulong)_zeroLeaf)
                return;

            ulong* leaf = (ulong*)NativeMemory.AlignedAlloc((nuint)SlotsPerLeaf * 8, 64);
            new Span<ulong>(leaf, SlotsPerLeaf).Fill((ulong)_zeroRecord);
            Volatile.Write(ref _top[top], (ulong)leaf);
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            for (ulong t = 0; t < TopCount; t++)
            {
                if (_top[t] != (ulong)_zeroLeaf)
                    NativeMemory.AlignedFree((void*)_top[t]);
            }
            foreach (IntPtr record in _records)
                NativeMemory.AlignedFree((void*)record);
            _records.Clear();
            NativeMemory.AlignedFree(_top);
            NativeMemory.AlignedFree(_zeroLeaf);
            NativeMemory.AlignedFree(_zeroRecord);
            NativeMemory.AlignedFree(_sink);
        }
    }
}
