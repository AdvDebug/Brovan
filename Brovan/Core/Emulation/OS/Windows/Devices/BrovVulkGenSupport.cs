using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed unsafe class GenReader
    {
        private byte[] _data;
        private int _base;
        private int _len;
        private int _pos;

        public void Reset(byte[] data, int offset, int len)
        {
            _data = data ?? Array.Empty<byte>();
            _base = offset < 0 ? 0 : offset;
            int max = _data.Length - _base;
            _len = len < 0 || len > max ? max : len;
            _pos = 0;
        }

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || (long)_pos + n > _len)
                throw new IndexOutOfRangeException("BrovVulk generic reader overrun.");
            ReadOnlySpan<byte> s = _data.AsSpan(_base + _pos, n);
            _pos += n;
            return s;
        }

        public uint ReadU32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));

        public ulong ReadU64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));

        public void CopyInto(IntPtr dst, uint n)
        {
            ReadOnlySpan<byte> s = Take((int)n);
            s.CopyTo(new Span<byte>((void*)dst, (int)n));
        }
    }

    internal sealed unsafe class GenBuf
    {
        private byte[] _data = new byte[256];
        private int _len;

        public void Reset() => _len = 0;

        private void Ensure(int extra)
        {
            if (_len + extra <= _data.Length)
                return;
            int newCap = Math.Max(_data.Length * 2, _len + extra);
            Array.Resize(ref _data, newCap);
        }

        public void WriteU32(uint value)
        {
            Ensure(4);
            BinaryPrimitives.WriteUInt32LittleEndian(_data.AsSpan(_len, 4), value);
            _len += 4;
        }

        public void WriteU64(ulong value)
        {
            Ensure(8);
            BinaryPrimitives.WriteUInt64LittleEndian(_data.AsSpan(_len, 8), value);
            _len += 8;
        }

        public void WriteBytesFrom(IntPtr src, uint n)
        {
            Ensure((int)n);
            new ReadOnlySpan<byte>((void*)src, (int)n).CopyTo(_data.AsSpan(_len, (int)n));
            _len += (int)n;
        }

        public byte[] Finish(int result)
        {
            byte[] outp = new byte[4 + _len];
            BinaryPrimitives.WriteInt32LittleEndian(outp.AsSpan(0, 4), result);
            if (_len > 0)
                Array.Copy(_data, 0, outp, 4, _len);
            return outp;
        }
    }

    internal static class BrovVulkGenNative
    {
        [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW")]
        internal static extern IntPtr GetModuleHandleW(IntPtr lpModuleName);
    }

    internal sealed class GenState
    {
        internal readonly struct MapEntry
        {
            public readonly IntPtr HostPtr;
            public readonly ulong GuestVa;
            public readonly ulong MapOffset;
            public readonly ulong Size;

            public MapEntry(IntPtr hostPtr, ulong guestVa, ulong mapOffset, ulong size)
            {
                HostPtr = hostPtr;
                GuestVa = guestVa;
                MapOffset = mapOffset;
                Size = size;
            }
        }

        private const int ArenaCap = 1 << 20;

        private readonly Dictionary<uint, (IntPtr Ptr, string Type)> _handles = new Dictionary<uint, (IntPtr, string)>();
        private readonly Dictionary<uint, MapEntry> _mappings = new Dictionary<uint, MapEntry>();
        private uint _next = 1;

        private IntPtr _arena;
        private int _arenaUsed;
        private readonly List<IntPtr> _overflow = new List<IntPtr>();

        public uint Register(IntPtr ptr, string type)
        {
            if (ptr == IntPtr.Zero)
                return 0;
            uint id = _next++;
            _handles[id] = (ptr, type);
            return id;
        }

        public IntPtr Lookup(uint id, string type)
        {
            if (id == 0)
                return IntPtr.Zero;
            if (_handles.TryGetValue(id, out (IntPtr Ptr, string Type) e) && e.Type == type)
                return e.Ptr;
            throw new InvalidOperationException($"BrovVulk generic: bad handle id {id} (expected {type}).");
        }

        public void Forget(uint id)
        {
            _handles.Remove(id);
            _mappings.Remove(id);
        }

        public bool HasMapping(uint id) => _mappings.ContainsKey(id);

        public void AddMapping(uint id, IntPtr hostPtr, ulong guestVa, ulong mapOffset, ulong size) =>
            _mappings[id] = new MapEntry(hostPtr, guestVa, mapOffset, size);

        public bool TryGetMapping(uint id, out MapEntry entry) => _mappings.TryGetValue(id, out entry);

        public void RemoveMapping(uint id) => _mappings.Remove(id);

        public void ClearMappings() => _mappings.Clear();

        public Dictionary<uint, MapEntry>.ValueCollection Mappings => _mappings.Values;

        public unsafe IntPtr Alloc(int size)
        {
            if (size <= 0)
                throw new InvalidOperationException($"BrovVulk generic: invalid allocation size {size}.");

            int aligned = (size + 15) & ~15;
            if (_arena == IntPtr.Zero)
                _arena = Marshal.AllocHGlobal(ArenaCap);

            if (aligned <= ArenaCap - _arenaUsed)
            {
                IntPtr p = _arena + _arenaUsed;
                _arenaUsed += aligned;
                new Span<byte>((void*)p, size).Clear();
                return p;
            }

            IntPtr q = Marshal.AllocHGlobal(size);
            new Span<byte>((void*)q, size).Clear();
            _overflow.Add(q);
            return q;
        }

        public void FreeCallAllocs()
        {
            _arenaUsed = 0;
            if (_overflow.Count == 0)
                return;
            foreach (IntPtr p in _overflow)
                Marshal.FreeHGlobal(p);
            _overflow.Clear();
        }
    }
}
