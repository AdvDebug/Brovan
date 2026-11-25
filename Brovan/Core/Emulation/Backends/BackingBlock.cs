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
        // The guest address of the block's first byte, for a block that backs one guest range at a fixed offset; else 0.
        public ulong GuestBase;
        public int LivePages;
        public int AliasPages;
        public int ParkedPages;
        public LinkedListNode<BackingBlock> ParkedNode;
        public int Pins;
        public bool Held;
        public IDisposable Owner;

        public bool IsHeldOrPinned => Held || Pins > 0;

        public bool IsReferenced => LivePages > 0 || AliasPages > 0 || ParkedPages > 0 || IsHeldOrPinned;

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

        // A live page of the block left: the binding's own per-page state, such as a window slot.
        void PageLeft(T Block, IntPtr HostPage);

        // An alias page left a block that can discard again: the pages that left meanwhile go now.
        void AliasLeft(T Block);

        void MarkPageDirty(ulong Guest);

        void RebuildMappings();
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

        private const ulong PageSize = 0x1000;

        private readonly BackingTable<T> _table;
        private readonly IBackingFreeSite<T> _site;
        private readonly GuestPaging _paging;
        private readonly List<IntPtr> _released = new();
        private readonly LinkedList<BackingBlock> _parkedBlocks = new();
        private readonly Queue<Batch> _sealed = new();
        private Batch _open;
        private IBackendHost _host;
        private ulong _deferredBytes;
        private int _sealedCount;

        public readonly HostDiscardRuns Discards = new();

        public BackingFrees(BackingTable<T> Table, IBackingFreeSite<T> Site, GuestPaging Paging)
        {
            _table = Table;
            _site = Site;
            _paging = Paging;
        }

        public void UseHost(IBackendHost Host) => _host = Host;

        public bool HasDeferred => Volatile.Read(ref _sealedCount) != 0 || _open != null;

        // A worker can still copy through a page it found before the unmap, so deferred host memory goes once every
        // other worker has passed a quiescent point. A page committed again before that is zeroed in place instead.
        private bool Defers => _host != null && _host.DefersHostFrees;

        public void Released(IntPtr Base) => _released.Add(Base);

        public void AddLive(T Block, int Pages)
        {
            if (Block.LivePages == 0)
                Unpark(Block);
            Block.LivePages += Pages;
        }

        // The page has left the page map. A parked page keeps its partition mapping, and its record holds one block
        // reference until it is revived or dropped.
        public void ReleasePage(ulong Guest, GuestPage Page, bool Park)
        {
            if (Page.OwnedBacking == IntPtr.Zero || !_table.TryGet(Page.OwnedBacking, out T Block))
                return;

            if (Page.IsAlias)
            {
                Block.AliasPages--;
            }
            else
            {
                Block.LivePages--;
                _site.PageLeft(Block, Page.HostPage);
                if (Park)
                {
                    Block.ParkedPages++;
                    _paging.Park(Guest, Page);
                }
                if (Block.LivePages == 0 && Block.ParkedPages != 0)
                    KeepParked(Block);
            }

            if (!Block.IsReferenced)
                Released(Page.OwnedBacking);
            else if (!Block.IsDiscardable)
                return;
            else if (!Page.IsAlias)
                Discards.Add(Page.OwnedBacking, Page.HostPage, PageSize);
            else
                _site.AliasLeft(Block);
        }

        // Revives the parked pages in the range that the new map gives their own host page, and drops the others. A
        // dropped page's map goes before any PTE names its address again.
        public bool EndParking(ulong Address, ulong Size, IntPtr HostBase)
        {
            bool Revived = false;
            bool Dropped = false;
            ulong End = Address + Size;
            ulong Cursor = Address;
            while (_paging.TryTakeParked(Cursor, End, Address, HostBase, out ulong Guest, out GuestPage Parked, out bool Same))
            {
                ReleaseParked(Parked);
                Revived |= Same;
                if (!Same)
                {
                    Dropped = true;
                    _site.MarkPageDirty(Guest);
                }
                Cursor = Guest + PageSize;
            }

            if (Dropped)
                _site.RebuildMappings();
            return Revived;
        }

        // The caller removes the maps of the range: by the rebuild that MarkDirty asks for, or by an unmap it already made.
        public void DropParked(ulong Start, ulong End, bool MarkDirty)
        {
            ulong Cursor = Start;
            while (_paging.TryTakeParked(Cursor, End, Start, IntPtr.Zero, out ulong Guest, out GuestPage Parked, out _))
            {
                ReleaseParked(Parked);
                if (MarkDirty)
                    _site.MarkPageDirty(Guest);
                Cursor = Guest + PageSize;
            }
        }

        // A commit of a range whose every page is parked in one guest-placed block takes those pages again, zeroed now.
        public bool TryReviveRange(ulong Address, ulong Size, out IntPtr Base, out IntPtr Host)
        {
            Base = IntPtr.Zero;
            Host = IntPtr.Zero;
            if (!_paging.TryGetNextParked(Address, Address + PageSize, out _, out GuestPage First)
                || !_table.TryGet(First.OwnedBacking, out T Block)
                || Block.GuestBase == 0
                || !Block.IsDiscardable
                || Address < Block.GuestBase
                || Size > Block.Size - (Address - Block.GuestBase))
                return false;

            IntPtr Start = new IntPtr(First.OwnedBacking.ToInt64() + (long)(Address - Block.GuestBase));
            for (ulong Offset = 0; Offset < Size; Offset += PageSize)
            {
                if (!_paging.IsParkedAt(Address + Offset, new IntPtr(Start.ToInt64() + (long)Offset)))
                    return false;
            }

            if (!HostDiscard.ZeroUnderReaders(Start, Size))
                return false;

            AddLive(Block, (int)(Size / PageSize));
            Base = First.OwnedBacking;
            Host = Start;
            return true;
        }

        private void ReleaseParked(GuestPage Parked)
        {
            if (!_table.TryGet(Parked.OwnedBacking, out T Block))
                return;

            if (--Block.ParkedPages == 0)
                Unpark(Block);
            if (!Block.IsReferenced)
                Released(Parked.OwnedBacking);
        }

        // A block whose live pages all left while it has parked pages stays for the next commit, up to
        // MemoryBudget.ParkedBlocks blocks, oldest first out.
        private void KeepParked(T Block)
        {
            if (Block.ParkedNode == null)
                Block.ParkedNode = _parkedBlocks.AddLast(Block);

            while (_parkedBlocks.Count > MemoryBudget.ParkedBlocks)
            {
                T Evicted = (T)_parkedBlocks.First!.Value;
                Unpark(Evicted);
                DropParked(Evicted.GuestBase, Evicted.GuestBase + Evicted.Size, true);
            }
        }

        private void Unpark(T Block)
        {
            if (Block.ParkedNode == null)
                return;

            _parkedBlocks.Remove(Block.ParkedNode);
            Block.ParkedNode = null;
        }

        public void Clear()
        {
            foreach (BackingBlock Block in _parkedBlocks)
                Block.ParkedNode = null;
            _parkedBlocks.Clear();
        }

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
