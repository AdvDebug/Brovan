using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation
{
    internal class BackingBlock
    {
        public ulong Size;
        public int LivePages;
        public int AliasPages;
        public int Pins;
        public bool Held;
        public IDisposable Owner;

        public bool IsHeldOrPinned => Held || Pins > 0;

        public bool IsReferenced => LivePages > 0 || AliasPages > 0 || IsHeldOrPinned;

        public bool IsDiscardable => !HostDiscard.Disabled && AliasPages == 0 && !IsHeldOrPinned && Owner == null;
    }

    internal sealed class BackingTable<T> where T : BackingBlock
    {
        private readonly Dictionary<IntPtr, T> _blocks = new();
        private readonly List<long> _starts = new();

        public int Count => _blocks.Count;

        public bool TryGet(IntPtr Base, out T Block) => _blocks.TryGetValue(Base, out Block);

        public void Add(IntPtr Base, T Block)
        {
            _blocks[Base] = Block;

            int Index = _starts.BinarySearch(Base.ToInt64());
            if (Index < 0)
                _starts.Insert(~Index, Base.ToInt64());
        }

        public void Remove(IntPtr Base)
        {
            _blocks.Remove(Base);

            int Index = _starts.BinarySearch(Base.ToInt64());
            if (Index >= 0)
                _starts.RemoveAt(Index);
        }

        public IntPtr Find(IntPtr HostPointer)
        {
            long Target = HostPointer.ToInt64();
            int Index = _starts.BinarySearch(Target);
            if (Index < 0)
                Index = ~Index - 1;

            if (Index < 0)
                return IntPtr.Zero;

            IntPtr Start = new IntPtr(_starts[Index]);
            return _blocks.TryGetValue(Start, out T Block) && (ulong)(Target - Start.ToInt64()) < Block.Size
                ? Start
                : IntPtr.Zero;
        }

        public IntPtr FindRange(IntPtr HostPointer, ulong Size, out T Block)
        {
            Block = null;
            IntPtr Base = Find(HostPointer);
            if (Base == IntPtr.Zero || Size == 0 || !_blocks.TryGetValue(Base, out Block)
                || Size > Block.Size - (ulong)(HostPointer.ToInt64() - Base.ToInt64()))
                return IntPtr.Zero;

            return Base;
        }

        public T TakeHold(IntPtr Base)
        {
            if (!_blocks.TryGetValue(Base, out T Block) || !Block.Held)
                return null;

            Block.Held = false;
            return Block;
        }

        public Dictionary<IntPtr, T>.Enumerator GetEnumerator() => _blocks.GetEnumerator();

        public void Clear()
        {
            _blocks.Clear();
            _starts.Clear();
        }
    }

    internal interface IBackingFreeSite<T> where T : BackingBlock
    {
        // After a failed unmap the hypervisor still maps the memory, so it is not freed.
        bool IsBackingStillMapped(IntPtr Start, ulong Size);

        void ForgetBlock(IntPtr Base, T Block);

        void FreeBlock(IntPtr Base, T Block);

        void DiscardRun(HostDiscardRuns.Run Run, T Block);
    }

    internal sealed class BackingFrees<T> where T : BackingBlock
    {
        private struct Entry
        {
            public IntPtr Base;
            public T Block;
            public HostDiscardRuns.Run Run;
        }

        private sealed class Batch
        {
            public readonly List<Entry> Entries = new();
            public QuiescenceSnapshot Snapshot;
            public ulong Bytes;
            public long SealedAt;
        }

        private readonly BackingTable<T> _table;
        private readonly IBackingFreeSite<T> _site;
        private readonly List<IntPtr> _released = new();
        private readonly Queue<Batch> _sealed = new();
        private Batch _open;
        private IBackendHost _host;
        private ulong _deferredBytes;
        private int _sealedCount;

        public readonly HostDiscardRuns Discards = new();

        public BackingFrees(BackingTable<T> Table, IBackingFreeSite<T> Site)
        {
            _table = Table;
            _site = Site;
        }

        public void UseHost(IBackendHost Host) => _host = Host;

        public bool HasDeferred => Volatile.Read(ref _sealedCount) != 0 || _open != null;

        // A worker can still copy through a page it found before the unmap, so deferred host memory goes once every other
        // worker has passed a quiescent point.
        private bool Defers => _host != null && _host.DefersHostFrees;

        public void Released(IntPtr Base) => _released.Add(Base);

        // A block that was never mapped has no reader to wait for.
        public void FreeUnpublished(IntPtr Base, T Block)
        {
            if (Block.IsReferenced)
                return;

            _table.Remove(Base);
            _site.ForgetBlock(Base, Block);
            _site.FreeBlock(Base, Block);
        }

        public void FreeIfUnreferenced(IntPtr Base, T Block)
        {
            if (Block.IsReferenced || _site.IsBackingStillMapped(Base, Block.Size))
                return;

            _table.Remove(Base);
            if (Discards.Count != 0)
                Discards.Remove(Base);
            _site.ForgetBlock(Base, Block);

            if (Defers)
                Defer(new Entry { Base = Base, Block = Block }, Block.Size);
            else
                _site.FreeBlock(Base, Block);
        }

        // Runs after the rebuild has unmapped the released pages, because other processors reach the backing until then.
        public void Flush()
        {
            for (int i = 0; i < _released.Count; i++)
            {
                if (_table.TryGet(_released[i], out T Block))
                    FreeIfUnreferenced(_released[i], Block);
            }

            _released.Clear();

            bool Deferring = Defers;
            for (int i = 0; i < Discards.Count; i++)
            {
                HostDiscardRuns.Run Run = Discards[i];
                if (!TryGetDiscardable(Run, out T Block))
                    continue;

                if (Deferring)
                    Defer(new Entry { Run = Run }, Run.Size);
                else
                    _site.DiscardRun(Run, Block);
            }

            Discards.Clear();
            Settle();
        }

        public void Settle()
        {
            Seal();
            CompletePassedIfAny();
        }

        private void Seal()
        {
            Batch Open = _open;
            if (Open == null)
                return;

            _open = null;
            Open.Snapshot = _host.TakeQuiescence();
            Open.SealedAt = Stopwatch.GetTimestamp();
            _sealed.Enqueue(Open);
            Volatile.Write(ref _sealedCount, _sealed.Count);
            _deferredBytes += Open.Bytes;
            DeferredFreeStats.Sealed(Open.Bytes);

            if (_deferredBytes > MemoryBudget.PendingFreeBytes)
            {
                DeferredFreeStats.OverBudget();
                _host.RequestQuiescentWait();
            }
        }

        public void CompletePassedIfAny()
        {
            if (_sealed.Count != 0)
                CompletePassed(false);
        }

        // Oldest first, because a run discarded late must not reach a block whose later free gave its host range back.
        public bool CompletePassed(bool All)
        {
            while (_sealed.Count != 0)
            {
                Batch Head = _sealed.Peek();
                if (!All && !_host.HasPassed(Head.Snapshot))
                    break;

                _sealed.Dequeue();
                _deferredBytes -= Head.Bytes;
                DeferredFreeStats.Completed(Stopwatch.GetTimestamp() - Head.SealedAt);
                RunEntries(Head);
            }

            if (All && _open != null)
            {
                RunEntries(_open);
                _open = null;
            }

            Volatile.Write(ref _sealedCount, _sealed.Count);
            return _deferredBytes > MemoryBudget.PendingFreeBytes;
        }

        private void Defer(in Entry Item, ulong Bytes)
        {
            Batch Open = _open ??= new Batch();
            Open.Entries.Add(Item);
            Open.Bytes += Bytes;
        }

        private void RunEntries(Batch Done)
        {
            List<Entry> Entries = Done.Entries;
            for (int i = 0; i < Entries.Count; i++)
            {
                Entry Item = Entries[i];
                if (Item.Block != null)
                    _site.FreeBlock(Item.Base, Item.Block);
                else if (TryGetDiscardable(Item.Run, out T Block))
                    _site.DiscardRun(Item.Run, Block);
            }
        }

        private bool TryGetDiscardable(in HostDiscardRuns.Run Run, out T Block)
            => _table.TryGet(Run.Key, out Block) && Block.IsDiscardable && !_site.IsBackingStillMapped(Run.Start, Run.Size);
    }

    internal static class DeferredFreeStats
    {
        private const int SealedIndex = 0;
        private const int SealedBytesIndex = 1;
        private const int CompletedIndex = 2;
        private const int WaitTicksIndex = 3;
        private const int OverBudgetIndex = 4;
        private const int TickIndex = 5;

        private static readonly PeriodicStats Log = new PeriodicStats("BROVAN_DEFERRED_FREE_STATS", "Deferred host frees:", Describe);
        private static readonly StatsSlots Slots = new StatsSlots(TickIndex + 1);

        internal static void Sealed(ulong Bytes)
        {
            if (!Log.Enabled)
                return;

            long[] S = Slots.Current.Values;
            S[SealedIndex]++;
            S[SealedBytesIndex] += (long)Bytes;
            Log.TickSlot(ref S[TickIndex]);
        }

        internal static void Completed(long WaitTicks)
        {
            if (!Log.Enabled)
                return;

            long[] S = Slots.Current.Values;
            S[CompletedIndex]++;
            S[WaitTicksIndex] += WaitTicks;
        }

        internal static void OverBudget()
        {
            if (Log.Enabled)
                Slots.Current.Values[OverBudgetIndex]++;
        }

        private static void Describe(StringBuilder sb)
        {
            long Completed = Slots.Sum(CompletedIndex);
            double WaitUs = Completed == 0 ? 0 : Slots.Sum(WaitTicksIndex) * 1e6 / Stopwatch.Frequency / Completed;
            sb.Append(" batches=").Append(Slots.Sum(SealedIndex))
              .Append(" bytes=").Append(Slots.Sum(SealedBytesIndex))
              .Append(" completed=").Append(Completed)
              .Append(" meanWaitUs=").Append(WaitUs.ToString("F1"))
              .Append(" overBudget=").Append(Slots.Sum(OverBudgetIndex));
        }
    }
}
