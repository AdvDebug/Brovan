using System.Collections;
using System.Runtime.CompilerServices;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation
{
    // The region list, the freed list and their lock. A probe reads the lists without the lock through the
    // sequence, which is odd while a change edits them.
    internal sealed class AddressSpace
    {
        internal readonly RankedLock Lock = new("AddressSpace", RankedLock.AddressSpaceRank);
        internal readonly RegionList<MemoryRegion> Regions;
        internal readonly RegionList<FreedRange> Freed;

        private long _sequence;
        private int _windowDepth;

        // Every list access asserts, so the check costs one field read when the order check is off.
        private readonly bool _checked = RankedLock.OrderChecked;

        internal AddressSpace()
        {
            Regions = new RegionList<MemoryRegion>(this);
            Freed = new RegionList<FreedRange>(this);
        }

        // Held by a change from its search to its last edit, backend calls included. A nested hold takes nothing.
        internal RankedLock.Scope Hold() => Lock.IsHeld ? default : Lock.EnterScope();

        // Around one group of edits that only make sense together. A backend call never runs inside one.
        internal Window Change() => new Window(this);

        internal readonly ref struct Window
        {
            private readonly AddressSpace _owner;
            private readonly bool _entered;

            internal Window(AddressSpace Owner)
            {
                _owner = Owner;
                _entered = !Owner.Lock.IsHeld;
                if (_entered)
                    Owner.Lock.Enter();
                if (Owner._windowDepth++ == 0)
                    Interlocked.Increment(ref Owner._sequence);
            }

            public void Dispose()
            {
                if (--_owner._windowDepth == 0)
                    Volatile.Write(ref _owner._sequence, _owner._sequence + 1);
                if (_entered)
                    _owner.Lock.Exit();
            }
        }

        internal void AssertChanging(string Where)
        {
            if (!_checked)
                return;

            Lock.AssertHeld(Where);
            if (Lock.IsHeld && _windowDepth == 0)
                RankedLock.FailOrder($"{Where} changes the address space outside a window.");
        }

        internal void AssertLocked(string Where)
        {
            if (_checked)
                Lock.AssertHeld(Where);
        }

        // The sequence a read starts from, once no window is open. The holder of the lock reads the lists as they stand.
        internal long BeginRead()
        {
            long Sequence = Volatile.Read(ref _sequence);
            if ((Sequence & 1) == 0 || Lock.IsHeld)
                return Sequence;

            Count(Waited);
            SpinWait Spin = default;
            while (((Sequence = Volatile.Read(ref _sequence)) & 1) != 0)
                Spin.SpinOnce();
            return Sequence;
        }

        // A read whose sequence still stands saw no change; otherwise it reads again.
        internal bool EndRead(long Sequence)
        {
            Volatile.ReadBarrier();
            if (Volatile.Read(ref _sequence) == Sequence)
                return true;

            Count(Retried);
            return false;
        }

        private const int Waited = 0;
        private const int Retried = 1;
        private const int Ticks = 2;
        private static readonly PeriodicStats Stats = new("BROVAN_ADDRESS_SPACE_STATS", "Address space reads:", DescribeStats);
        private static readonly StatsSlots Slots = new(Ticks + 1);

        // Only the slow paths count: a read that met an open window, and one that read again.
        private static void Count(int Index)
        {
            if (!Stats.Enabled)
                return;

            long[] S = Slots.Current.Values;
            S[Index]++;
            Stats.TickSlot(ref S[Ticks]);
        }

        private static void DescribeStats(StringBuilder Text) =>
            Text.Append(" waited=").Append(Slots.Sum(Waited)).Append(" retried=").Append(Slots.Sum(Retried));

        internal void ReportStats()
        {
            if (Stats.Enabled)
                Stats.Report();
        }

        internal void Clear()
        {
            using Window Changing = Change();
            Regions.Clear();
            Freed.Clear();
        }
    }

    // A list the address space keeps sorted. Every call but Snapshot belongs to a holder of the address space lock.
    internal sealed class RegionList<T> : IEnumerable<T> where T : struct
    {
        private readonly AddressSpace _owner;
        private T[] _items = new T[64];
        private int _count;

        internal RegionList(AddressSpace Owner) => _owner = Owner;

        public int Count
        {
            get
            {
                _owner.AssertLocked("A region list count");
                return _count;
            }
        }

        public T this[int Index]
        {
            get
            {
                if ((uint)Index >= (uint)_count)
                    ThrowIndex();
                _owner.AssertLocked("A region list read");
                return _items[Index];
            }
            set
            {
                if ((uint)Index >= (uint)_count)
                    ThrowIndex();
                _owner.AssertChanging("A region list store");
                _items[Index] = value;
            }
        }

        // For a probe between BeginRead and EndRead. A change can grow the array under it, so the count is cut to the
        // array it read.
        internal ReadOnlySpan<T> Snapshot
        {
            get
            {
                T[] Items = Volatile.Read(ref _items);
                int Count = Volatile.Read(ref _count);
                return Items.AsSpan(0, Math.Min(Count, Items.Length));
            }
        }

        public Span<T> AsSpan()
        {
            _owner.AssertLocked("A region list span");
            return _items.AsSpan(0, _count);
        }

        public void Insert(int Index, T Item)
        {
            if ((uint)Index > (uint)_count)
                ThrowIndex();
            _owner.AssertChanging("A region list insert");
            EnsureCapacity(_count + 1);
            Array.Copy(_items, Index, _items, Index + 1, _count - Index);
            _items[Index] = Item;
            _count++;
        }

        public void InsertRange(int Index, List<T> Items)
        {
            if ((uint)Index > (uint)_count)
                ThrowIndex();
            _owner.AssertChanging("A region list insert");
            int Added = Items.Count;
            EnsureCapacity(_count + Added);
            Array.Copy(_items, Index, _items, Index + Added, _count - Index);
            Items.CopyTo(_items, Index);
            _count += Added;
        }

        public void RemoveAt(int Index) => RemoveRange(Index, 1);

        public void RemoveRange(int Index, int Count)
        {
            if (Index < 0 || Count < 0 || Index > _count - Count)
                ThrowIndex();
            _owner.AssertChanging("A region list removal");
            Array.Copy(_items, Index + Count, _items, Index, _count - Index - Count);
            _count -= Count;
            Array.Clear(_items, _count, Count);
        }

        public int RemoveAll(Predicate<T> Match)
        {
            _owner.AssertChanging("A region list removal");
            int Kept = 0;
            for (int i = 0; i < _count; i++)
            {
                if (!Match(_items[i]))
                    _items[Kept++] = _items[i];
            }

            int Removed = _count - Kept;
            Array.Clear(_items, Kept, Removed);
            _count = Kept;
            return Removed;
        }

        public int BinarySearch(T Item, IComparer<T> Comparer)
        {
            _owner.AssertLocked("A region list search");
            return Array.BinarySearch(_items, 0, _count, Item, Comparer);
        }

        public void Sort(IComparer<T> Comparer)
        {
            _owner.AssertChanging("A region list sort");
            Array.Sort(_items, 0, _count, Comparer);
        }

        public void Clear()
        {
            _owner.AssertChanging("A region list clear");
            Array.Clear(_items, 0, _count);
            _count = 0;
        }

        // A grown array is filled before it is published, so a probe that reads it sees whole entries.
        private void EnsureCapacity(int Needed)
        {
            if (Needed <= _items.Length)
                return;

            T[] Grown = new T[Math.Max(Needed, _items.Length * 2)];
            Array.Copy(_items, Grown, _count);
            Volatile.Write(ref _items, Grown);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void ThrowIndex() => throw new ArgumentOutOfRangeException("Index");

        public Enumerator GetEnumerator() => new Enumerator(this);

        IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public struct Enumerator : IEnumerator<T>
        {
            private readonly RegionList<T> _list;
            private int _index;

            internal Enumerator(RegionList<T> List)
            {
                List._owner.AssertLocked("A region list walk");
                _list = List;
                _index = -1;
            }

            public T Current => _list._items[_index];

            object IEnumerator.Current => Current;

            public bool MoveNext() => ++_index < _list._count;

            public void Reset() => _index = -1;

            public void Dispose()
            {
            }
        }
    }
}
