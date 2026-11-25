using System;
using System.Numerics;
using System.Threading;

namespace Brovan.Core.Emulation
{
    [Flags]
    public enum GuestPagePermission
    {
        None = 0,
        Read = 1,
        Write = 2,
        Execute = 4,
        ReadWrite = Read | Write,
        WriteExecute = Write | Execute,
        ReadExecute = Read | Execute,
        All = Read | Write | Execute,
    }

    internal sealed class GuestPage
    {
        public IntPtr HostPage { get; init; }
        public IntPtr OwnedBacking { get; init; }
        public bool IsAlias { get; init; }
        public GuestPagePermission Permissions { get; init; }
        public bool WriteRetained { get; init; }

        // Only the watch state changes in place, so a reader without a lock sees one whole mapping.
        public bool WriteWatched;
        public bool Written;
        public bool Untouched;

        public GuestPage WithPermissions(GuestPagePermission Permissions, bool WriteRetained) => new GuestPage
        {
            HostPage = HostPage,
            OwnedBacking = OwnedBacking,
            IsAlias = IsAlias,
            Permissions = Permissions,
            WriteRetained = WriteRetained,
            WriteWatched = WriteWatched,
            Written = Written,
            Untouched = Untouched,
        };
    }

    internal sealed class GuestPageMap
    {
        private const int PageShift = 12;
        private const ulong PageSize = 1UL << PageShift;
        private const int LevelBits = 9;
        private const int Fanout = 1 << LevelBits;
        private const int SlotMask = Fanout - 1;

        private sealed class Node
        {
            public readonly Node?[]? Children;
            public readonly GuestPage?[]? Pages;
            public int Live;

            public Node(bool leaf)
            {
                if (leaf)
                    Pages = new GuestPage[Fanout];
                else
                    Children = new Node[Fanout];
            }
        }

        private readonly ulong _pageLimit;
        private readonly int _topShift;
        private Node _root;
        private IBackendHost? _checkHost;

        public GuestPageMap(ulong addressLimit)
        {
            _pageLimit = addressLimit >> PageShift;
            if (_pageLimit < 2)
                throw new ArgumentOutOfRangeException(nameof(addressLimit));

            int bits = BitOperations.Log2(_pageLimit - 1) + 1;
            _topShift = (bits - 1) / LevelBits * LevelBits;
            _root = new Node(_topShift == 0);
        }

        public ulong AddressLimit => _pageLimit << PageShift;

        public void CheckReaders(IBackendHost host) => _checkHost = host;

        // Get takes no lock. The writers run under the mapping lock and publish each slot last.
        public GuestPage? Get(ulong address)
        {
            if (_checkHost != null)
            {
                if (!_checkHost.DefersHostFrees)
                    RankedLock.AssertOneHeld(_checkHost.RunLock, _checkHost.MappingLock, "A guest page lookup");
                else if (!_checkHost.MayReadPagesWithoutLock)
                    _checkHost.MappingLock.AssertHeld("A guest page lookup");
            }

            ulong number = address >> PageShift;
            if (number >= _pageLimit)
                return null;

            Node? node = Volatile.Read(ref _root);
            for (int shift = _topShift; shift != 0; shift -= LevelBits)
            {
                node = Volatile.Read(ref node.Children![(int)(number >> shift) & SlotMask]);
                if (node == null)
                    return null;
            }
            return Volatile.Read(ref node.Pages![(int)number & SlotMask]);
        }

        public bool TryGetValue(ulong address, out GuestPage page)
        {
            GuestPage? found = Get(address);
            page = found!;
            return found != null;
        }

        public bool ContainsKey(ulong address) => Get(address) != null;

        public bool ContinuesHostRun(ulong pageAddress, GuestPage first, ulong end)
        {
            for (ulong cursor = pageAddress + PageSize; cursor < end; cursor += PageSize)
            {
                GuestPage? next = Get(cursor);
                if (next == null || next.HostPage == IntPtr.Zero || next.OwnedBacking != first.OwnedBacking
                    || next.HostPage.ToInt64() != first.HostPage.ToInt64() + (long)(cursor - pageAddress))
                    return false;
            }
            return true;
        }

        public void Set(ulong address, GuestPage page)
        {
            ArgumentNullException.ThrowIfNull(page);
            ulong number = address >> PageShift;
            if (number >= _pageLimit)
                throw new ArgumentOutOfRangeException(nameof(address));

            Node node = _root;
            for (int shift = _topShift; shift != 0; shift -= LevelBits)
            {
                ref Node? child = ref node.Children![(int)(number >> shift) & SlotMask];
                if (child == null)
                {
                    Volatile.Write(ref child, new Node(shift == LevelBits));
                    node.Live++;
                }
                node = child!;
            }

            ref GuestPage? slot = ref node.Pages![(int)number & SlotMask];
            if (slot == null)
                node.Live++;
            Volatile.Write(ref slot, page);
        }

        public bool Remove(ulong address, out GuestPage removed)
        {
            ulong number = address >> PageShift;
            GuestPage? found = number < _pageLimit ? Remove(_root, _topShift, number) : null;
            removed = found!;
            return found != null;
        }

        // A reader that still holds a node removed from its parent reads only empty slots.
        private static GuestPage? Remove(Node node, int shift, ulong number)
        {
            int index = (int)(number >> shift) & SlotMask;
            if (shift == 0)
            {
                GuestPage? page = node.Pages![index];
                if (page == null)
                    return null;

                Volatile.Write(ref node.Pages[index], null);
                node.Live--;
                return page;
            }

            Node? child = node.Children![index];
            GuestPage? removed = child == null ? null : Remove(child, shift - LevelBits, number);
            if (removed != null && child!.Live == 0)
            {
                Volatile.Write(ref node.Children[index], null);
                node.Live--;
            }
            return removed;
        }

        public bool TryGetNext(ulong pageAddress, out ulong foundAddress, out GuestPage page)
            => TryGetNext(pageAddress, _pageLimit << PageShift, out foundAddress, out page);

        public bool TryGetNext(ulong pageAddress, ulong endAddress, out ulong foundAddress, out GuestPage page)
        {
            ulong number = pageAddress >> PageShift;
            ulong limit = Math.Min(_pageLimit, (endAddress + PageSize - 1) >> PageShift);
            ulong foundNumber = 0;
            GuestPage? found = number < limit ? FindNext(_root, _topShift, number, limit, out foundNumber) : null;
            foundAddress = foundNumber << PageShift;
            page = found!;
            return found != null;
        }

        private static GuestPage? FindNext(Node node, int shift, ulong number, ulong limit, out ulong found)
        {
            ulong nodeBase = number & ~((1UL << (shift + LevelBits)) - 1);
            int first = (int)(number >> shift) & SlotMask;
            for (int index = first; index < Fanout; index++)
            {
                ulong slotBase = nodeBase + ((ulong)index << shift);
                if (slotBase >= limit)
                    break;

                if (shift == 0)
                {
                    GuestPage? page = node.Pages![index];
                    if (page == null)
                        continue;

                    found = slotBase;
                    return page;
                }

                Node? child = node.Children![index];
                if (child == null)
                    continue;

                GuestPage? next = FindNext(child, shift - LevelBits, Math.Max(number, slotBase), limit, out found);
                if (next != null)
                    return next;
            }

            found = 0;
            return null;
        }

        public void Clear() => Volatile.Write(ref _root, new Node(_topShift == 0));
    }
}
