using System;
using System.Collections.Generic;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation
{
    internal interface IGuestPagingBackend
    {
        // An internal page with its record set, which the GPA map takes at the next rebuild.
        ulong AllocateTablePage();
    }

    internal enum WriteWatchStatus
    {
        Ok,
        InvalidArgument,
        Unmapped,
    }

    internal sealed unsafe class GuestPaging
    {
        private const ulong PageSize = 0x1000;
        private const ulong PageMask = PageSize - 1;

        private readonly IGuestPagingBackend _backend;
        private readonly GuestEntryGate _gate;
        private readonly GuestPageMap _pages;
        private readonly GuestPageMap _parked;
        private readonly ulong _internalBase;
        private RankedLock? _mappingLock;
        private RankedLock? _checkedLock;
        private IBackendHost? _host;
        private int _watchedPages;
        private int _untouchedPages;

        public GuestPaging(IGuestPagingBackend backend, GuestEntryGate gate, GuestPageMap pages, ulong internalBase)
        {
            _backend = backend;
            _gate = gate;
            _pages = pages;
            _parked = new GuestPageMap(pages.AddressLimit);
            _internalBase = internalBase;
        }

        public void UseHost(IBackendHost host)
        {
            _host = host;
            _mappingLock = host.MappingLock;
            if (!RankedLock.OrderChecked)
                return;

            _checkedLock = host.MappingLock;
            _pages.CheckReaders(host);
        }

        public bool TryReadPages(ulong address, Span<byte> buffer)
        {
            RecordHostAccess(address, (ulong)buffer.Length, false);

            RankedLock.Scope copyHold = default;
            bool locked = false;
            try
            {
                ulong current = address;
                int offset = 0;
                int remaining = buffer.Length;

                while (remaining > 0)
                {
                    ulong pageBase = current & ~PageMask;
                    if (!TryLookupForCopy(pageBase, ref copyHold, ref locked, out GuestPage page))
                        return false;

                    ulong pageOffset = current - pageBase;
                    int chunk = (int)Math.Min((ulong)remaining, PageSize - pageOffset);
                    Unsafe.CopyBlockUnaligned(
                        ref Unsafe.AsRef<byte>(ref buffer[offset]),
                        ref Unsafe.AsRef<byte>((void*)(page.HostPage + (int)pageOffset)),
                        (uint)chunk);

                    current += (ulong)chunk;
                    offset += chunk;
                    remaining -= chunk;
                }
                return true;
            }
            finally
            {
                copyHold.Dispose();
            }
        }

        public bool TryWritePages(ulong address, ReadOnlySpan<byte> buffer)
        {
            if (!InternalPages.IsGuestRange(address, (ulong)buffer.Length, _internalBase)) return false;

            RankedLock.Scope copyHold = default;
            bool locked = false;
            try
            {
                ulong current = address;
                int offset = 0;
                int remaining = buffer.Length;

                while (remaining > 0)
                {
                    ulong pageBase = current & ~PageMask;
                    if (!TryLookupForCopy(pageBase, ref copyHold, ref locked, out GuestPage page))
                        return false;

                    ulong pageOffset = current - pageBase;
                    int chunk = (int)Math.Min((ulong)remaining, PageSize - pageOffset);
                    Unsafe.CopyBlockUnaligned(
                        ref Unsafe.AsRef<byte>((void*)(page.HostPage + (int)pageOffset)),
                        ref Unsafe.AsRef<byte>(in buffer[offset]),
                        (uint)chunk);

                    current += (ulong)chunk;
                    offset += chunk;
                    remaining -= chunk;
                }
            }
            finally
            {
                copyHold.Dispose();
            }

            RecordHostAccess(address, (ulong)buffer.Length, true);
            return true;
        }

        public bool TryGetHostPointer(ulong address, int accessSize, bool write, out byte* ptr, out long offset)
        {
            ptr = null;
            offset = 0;
            if (accessSize <= 0 || !InternalPages.IsGuestRange(address, (ulong)accessSize, _internalBase)) return false;

            ulong pageBase = address & ~PageMask;
            if (NeedsLockToRead || !TryLookupPage(pageBase, out GuestPage page) || !MayCopyPage(page))
                return false;

            if (!_pages.ContinuesHostRun(pageBase, page, address + (ulong)accessSize))
                return false;

            ptr = (byte*)page.HostPage;
            offset = (long)(address - pageBase);
            RecordHostAccess(address, (ulong)accessSize, write);
            return true;
        }

        public RankedLock.Scope LockMappings() => _mappingLock != null ? _mappingLock.EnterScope() : default;

        // Where host frees are deferred, only a worker outside its quiescent spans reads the page records without the
        // mapping lock, and the frees wait for it. Every free holds that lock.
        private bool NeedsLockToRead
            => _host != null && _host.DefersHostFrees && !_host.MayReadPagesWithoutLock && !_mappingLock!.IsHeld;

        // Another owner frees foreign memory as soon as the unmap returns, and the unmap swaps the record under the
        // mapping lock, so such a page is copied under it.
        private bool MayCopyPage(GuestPage page)
            => page.OwnedBacking != IntPtr.Zero || _host == null || !_host.DefersHostFrees || _mappingLock!.IsHeld;

        // Once a copy needs the mapping lock, it holds it to the end and finds the page again under it.
        private bool TryLookupForCopy(ulong pageBase, ref RankedLock.Scope hold, ref bool locked, out GuestPage page)
        {
            if (!locked && NeedsLockToRead)
            {
                hold = LockMappings();
                locked = true;
            }

            if (!TryLookupPage(pageBase, out page))
                return false;
            if (locked || MayCopyPage(page))
                return true;

            hold = LockMappings();
            locked = true;
            return TryLookupPage(pageBase, out page);
        }

        public void AssertMappingsHeld(string where) => _checkedLock?.AssertHeld(where);

        public ulong Root { get; private set; }

        public void CreateRoot() => Root = _backend.AllocateTablePage();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryLookupPage(ulong pageBase, out GuestPage page)
        {
            if (_pages.TryGetValue(pageBase, out page) && page.HostPage != IntPtr.Zero)
                return true;

            page = null!;
            return false;
        }

        public bool IsRangeMapped(ulong address, ulong size)
        {
            if (size == 0)
                return true;
            if (!InternalPages.IsGuestRange(address, size, _internalBase))
                return false;

            ulong end = address + size;
            for (ulong pageBase = address & ~PageMask; pageBase < end; pageBase += PageSize)
            {
                if (!TryLookupPage(pageBase, out _))
                    return false;
            }
            return true;
        }

        // Present with the access, page by page. A caller that passes its trapped set holds the mapping lock.
        public bool IsRangeAccessible(ulong address, ulong size, bool write, Dictionary<ulong, bool>? trapped = null)
        {
            if (size == 0)
                return true;
            if (!InternalPages.IsGuestRange(address, size, _internalBase))
                return false;

            GuestAccess access = write ? GuestAccess.Write : GuestAccess.Read;
            ulong end = address + size;
            for (ulong pageBase = address & ~PageMask; pageBase < end; pageBase += PageSize)
            {
                if (!TryLookupPage(pageBase, out GuestPage page) || (trapped != null && trapped.ContainsKey(pageBase)))
                    return false;

                GuestPagePermission perm = page.Permissions;
                if (!GuestPageEntries.Allows((perm & GuestPagePermission.Read) != 0, (perm & GuestPagePermission.Write) != 0,
                        (perm & GuestPagePermission.Execute) != 0, access))
                    return false;
            }
            return true;
        }

        public void SetPage(ulong address, GuestPage page)
        {
            AssertMappingsHeld(nameof(SetPage));
            if (_checkedLock != null && ParkedCount != 0 && _parked.ContainsKey(address))
                RankedLock.FailOrder($"A page set at 0x{address:X} is still parked.");
            if (_watchedPages != 0 && _pages.TryGetValue(address, out GuestPage replaced))
                ForgetWatchedPage(replaced);
            _pages.Set(address, page);
        }

        // The watch state moves with the changed copy, so the watch counts stay.
        public void ReplacePage(ulong address, GuestPage page)
        {
            AssertMappingsHeld(nameof(ReplacePage));
            _pages.Set(address, page);
        }

        public bool RemovePage(ulong address)
        {
            AssertMappingsHeld(nameof(RemovePage));
            if (!_pages.Remove(address, out GuestPage removed))
                return false;

            ForgetWatchedPage(removed);
            return true;
        }

        public void Clear()
        {
            _pages.Clear();
            _watchedPages = 0;
            _untouchedPages = 0;
            _parked.Clear();
            ParkedCount = 0;
        }

        // A parked page is a freed private page whose partition mapping stays installed for the next commit at its
        // address. Its PTE is not present, its host page is discarded, and its record holds one reference on its block.
        public static readonly bool ParkingDisabled = Environment.GetEnvironmentVariable("BROVAN_NO_PARKED_PAGES") == "1";

        public int ParkedCount { get; private set; }

        public void Park(ulong address, GuestPage page)
        {
            AssertMappingsHeld(nameof(Park));
            if (_checkedLock != null && _pages.ContainsKey(address))
                RankedLock.FailOrder($"A page parked at 0x{address:X} is still live.");
            _parked.Set(address, page);
            ParkedCount++;
            ParkedPageStats.Count(ParkedPageStats.Parked);
        }

        public bool IsParkedAt(ulong address, IntPtr hostPage)
            => ParkedCount != 0 && _parked.TryGetValue(address, out GuestPage page) && page.HostPage == hostPage;

        public bool TryGetNextParked(ulong from, ulong end, out ulong address, out GuestPage page)
        {
            AssertMappingsHeld(nameof(TryGetNextParked));
            if (ParkedCount != 0)
                return _parked.TryGetNext(from, end, out address, out page);

            address = 0;
            page = null!;
            return false;
        }

        // Takes the first parked page in [from, end). The caller gives back its block reference.
        public bool TryTakeParked(ulong from, ulong end, ulong mapStart, IntPtr hostBase, out ulong address, out GuestPage page, out bool revived)
        {
            AssertMappingsHeld(nameof(TryTakeParked));
            revived = false;
            if (ParkedCount == 0 || !_parked.TryGetNext(from, end, out address, out page))
            {
                address = 0;
                page = null!;
                return false;
            }

            _parked.Remove(address, out _);
            ParkedCount--;
            revived = hostBase != IntPtr.Zero && page.HostPage.ToInt64() == hostBase.ToInt64() + (long)(address - mapStart);
            ParkedPageStats.Count(revived ? ParkedPageStats.Revived : ParkedPageStats.Dropped);
            return true;
        }

        // Every caller holds the mapping lock of its emulator.
        private static class ParkedPageStats
        {
            internal const int Parked = 0;
            internal const int Revived = 1;
            internal const int Dropped = 2;

            private static readonly string[] Names = { "parked", "revived", "dropped" };
            private static readonly PeriodicStats Log = new PeriodicStats("BROVAN_PARKED_PAGE_STATS", "Parked pages:", Describe);
            private static readonly long[] Counts = new long[Names.Length];

            internal static void Count(int index)
            {
                if (!Log.Enabled)
                    return;

                Counts[index]++;
                Log.Tick();
            }

            private static void Describe(StringBuilder sb)
            {
                for (int i = 0; i < Counts.Length; i++)
                    sb.Append(' ').Append(Names[i]).Append('=').Append(Counts[i]);
            }
        }

        private void ForgetWatchedPage(GuestPage page)
        {
            if (page.WriteWatched)
                _watchedPages--;
            if (page.Untouched)
                _untouchedPages--;
        }

        private static int Index(ulong address, int shift) => (int)((address >> shift) & 0x1FF);

        // Returns true when access was removed and every processor needs a flush.
        public bool SetLeaf(ulong guestAddress, GuestPagePermission permissions)
        {
            AssertMappingsHeld(nameof(SetLeaf));
            ulong pageBase = guestAddress & ~PageMask;
            ulong* pt = (ulong*)PageTableView(EnsureChildTable(EnsureDirectoryTable(pageBase), Index(pageBase, 21)));
            if (pt == null)
                return false;

            ref ulong slot = ref pt[Index(pageBase, 12)];
            ulong entry = GuestPageEntries.Leaf(pageBase, permissions != GuestPagePermission.None,
                (permissions & GuestPagePermission.Write) != 0, (permissions & GuestPagePermission.Execute) != 0, _internalBase);

            ulong old;
            if (_watchedPages == 0)
            {
                old = slot;
                Volatile.Write(ref slot, entry);
            }
            else
            {
                _pages.TryGetValue(pageBase, out GuestPage page);

                // NT: an untouched page has no valid PTE until its first access.
                if (page != null && page.Untouched)
                    entry = 0;

                // Another processor can set the dirty bit until the swap.
                old = Interlocked.Exchange(ref slot, entry);
                if ((old & GuestPageEntries.Dirty) != 0 && page != null && page.WriteWatched)
                    page.Written = true;
            }

            return GuestPageEntries.RemovesAccess(old, entry);
        }

        public ulong EnsureDirectoryTable(ulong address)
            => EnsureChildTable(EnsureChildTable(Root, Index(address, 39)), Index(address, 30));

        public ulong EnsureChildTable(ulong tableGpa, int index, ulong newEntryFlags = GuestPageEntries.TableFlags)
        {
            ulong* entries = (ulong*)PageTableView(tableGpa);
            if (entries == null)
                return 0;

            ulong entry = entries[index];
            if (NamesTable(entry))
                return entry & GuestPageEntries.AddressMask;
            if ((entry & GuestPageEntries.Present) != 0)
                return 0;

            AssertMappingsHeld(nameof(EnsureChildTable));
            ulong childGpa = _backend.AllocateTablePage();
            entries[index] = childGpa | newEntryFlags;
            return childGpa;
        }

        public bool SetKernelLargePage(ulong address)
        {
            AssertMappingsHeld(nameof(SetKernelLargePage));
            ulong* directoryEntry = FindDirectoryEntry(address);
            if (directoryEntry == null)
                return false;

            Volatile.Write(ref *directoryEntry, address | GuestPageEntries.Present | GuestPageEntries.LargePage | GuestPageEntries.NoExecute);
            return true;
        }

        // Table pages are internal pages, so a guest page never reads as a table.
        public IntPtr PageTableView(ulong tableGpa)
            => tableGpa >= _internalBase && _pages.TryGetValue(tableGpa, out GuestPage page) ? page.HostPage : IntPtr.Zero;

        public ulong* FindLeafEntry(ulong pageBase, ref ulong* table, ref ulong tableRange)
        {
            if (pageBase >> 21 != tableRange)
            {
                table = FindLeafTable(pageBase);
                tableRange = pageBase >> 21;
            }

            return table == null ? null : table + Index(pageBase, 12);
        }

        private ulong* FindLeafTable(ulong pageBase)
        {
            ulong* directoryEntry = FindDirectoryEntry(pageBase);
            if (directoryEntry == null || !NamesTable(*directoryEntry))
                return null;

            return (ulong*)PageTableView(*directoryEntry & GuestPageEntries.AddressMask);
        }

        public ulong* FindDirectoryEntry(ulong pageBase)
        {
            ulong table = Root;
            for (int shift = 39; shift >= 30; shift -= 9)
            {
                ulong* view = (ulong*)PageTableView(table);
                if (view == null)
                    return null;

                ulong entry = view[Index(pageBase, shift)];
                if (!NamesTable(entry))
                    return null;
                table = entry & GuestPageEntries.AddressMask;
            }

            ulong* directory = (ulong*)PageTableView(table);
            return directory == null ? null : directory + Index(pageBase, 21);
        }

        private static bool NamesTable(ulong entry) =>
            (entry & GuestPageEntries.Present) != 0
                ? (entry & GuestPageEntries.LargePage) == 0
                : (entry & GuestPageEntries.Withheld) != 0;

        // NT: write watch uses the PTE dirty bit, which the processor sets with no exit.
        public WriteWatchStatus WatchWrites(ulong address, ulong size)
        {
            AssertMappingsHeld(nameof(WatchWrites));
            if ((address & PageMask) != 0 || (size & PageMask) != 0)
                return WriteWatchStatus.InvalidArgument;
            if (!IsRangeMapped(address, size))
                return WriteWatchStatus.Unmapped;

            ulong* table = null;
            ulong tableRange = ulong.MaxValue;
            for (ulong off = 0; off < size; off += PageSize)
            {
                ulong pageBase = address + off;
                GuestPage page = _pages.Get(pageBase)!;
                if (page.WriteWatched)
                    continue;

                page.WriteWatched = true;
                page.Written = false;
                page.Untouched = true;
                _watchedPages++;
                _untouchedPages++;

                // x86 sets the accessed bit before it caches a translation.
                ulong* entry = FindLeafEntry(pageBase, ref table, ref tableRange);
                if (entry != null && (Interlocked.Exchange(ref *entry, 0) & GuestPageEntries.Accessed) != 0)
                    TouchWatchedPage(pageBase, page);
            }
            return WriteWatchStatus.Ok;
        }

        // NT: the first access of a writable untouched page counts as a write.
        private void TouchWatchedPage(ulong pageBase, GuestPage page)
        {
            page.Untouched = false;
            _untouchedPages--;
            if ((page.Permissions & GuestPagePermission.Write) != 0)
                page.Written = true;
            SetLeaf(pageBase, page.Permissions);
        }

        public bool TryTouchWatchedPage(ulong errorCode, ulong faultAddress)
        {
            if (Volatile.Read(ref _untouchedPages) == 0 || (errorCode & GuestPageEntries.FaultPresent) != 0)
                return false;

            using RankedLock.Scope mappingHold = LockMappings();
            ulong pageBase = faultAddress & ~PageMask;
            if (!_pages.TryGetValue(pageBase, out GuestPage page) || !page.Untouched || page.Permissions == GuestPagePermission.None ||
                ((errorCode & GuestPageEntries.FaultWrite) != 0 && (page.Permissions & GuestPagePermission.Write) == 0))
                return false;

            TouchWatchedPage(pageBase, page);
            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void RecordHostAccess(ulong address, ulong length, bool write)
        {
            if (write ? Volatile.Read(ref _watchedPages) != 0 : Volatile.Read(ref _untouchedPages) != 0)
                RecordWatchedAccess(address, length, write);
        }

        private void RecordWatchedAccess(ulong address, ulong length, bool write)
        {
            if (length == 0)
                return;

            using RankedLock.Scope mappingHold = LockMappings();
            ulong end = address + length;
            for (ulong pageBase = address & ~PageMask; pageBase < end; pageBase += PageSize)
            {
                if (!TryLookupPage(pageBase, out GuestPage page) || !page.WriteWatched)
                    continue;

                if (page.Untouched && page.Permissions != GuestPagePermission.None)
                    TouchWatchedPage(pageBase, page);
                if (write)
                    page.Written = true;
            }
        }

        public WriteWatchStatus QueryWrites(ulong address, ulong pageCount, Span<ulong> written)
        {
            AssertMappingsHeld(nameof(QueryWrites));
            if ((address & PageMask) != 0 || pageCount > (ulong)written.Length * 64)
                return WriteWatchStatus.InvalidArgument;

            written.Slice(0, (int)((pageCount + 63) / 64)).Clear();

            ulong* table = null;
            ulong tableRange = ulong.MaxValue;
            for (ulong index = 0; index < pageCount; index++)
            {
                ulong pageBase = address + (index << 12);
                if (!_pages.TryGetValue(pageBase, out GuestPage page) || !page.WriteWatched)
                    continue;

                bool dirty = page.Written;
                if (!dirty)
                {
                    ulong* entry = FindLeafEntry(pageBase, ref table, ref tableRange);
                    dirty = entry != null && (Volatile.Read(ref *entry) & GuestPageEntries.Dirty) != 0;
                }

                if (dirty)
                    written[(int)(index >> 6)] |= 1UL << (int)(index & 63);
            }
            return WriteWatchStatus.Ok;
        }

        public WriteWatchStatus ResetWrites(ulong address, ulong pageCount, ReadOnlySpan<ulong> pages)
        {
            AssertMappingsHeld(nameof(ResetWrites));
            if ((address & PageMask) != 0 || pageCount > (ulong)pages.Length * 64)
                return WriteWatchStatus.InvalidArgument;

            ulong* table = null;
            ulong tableRange = ulong.MaxValue;
            bool cleared = false;
            int words = (int)((pageCount + 63) / 64);

            for (int word = 0; word < words; word++)
            {
                for (ulong bits = pages[word]; bits != 0; bits &= bits - 1)
                {
                    ulong index = (ulong)word * 64 + (ulong)BitOperations.TrailingZeroCount(bits);
                    if (index >= pageCount)
                        break;

                    ulong pageBase = address + (index << 12);
                    if (!_pages.TryGetValue(pageBase, out GuestPage page) || !page.WriteWatched)
                        continue;

                    cleared |= page.Written;
                    page.Written = false;
                    ulong* entry = FindLeafEntry(pageBase, ref table, ref tableRange);
                    if (entry != null && (Interlocked.And(ref *entry, ~GuestPageEntries.Dirty) & GuestPageEntries.Dirty) != 0)
                        cleared = true;
                }
            }

            // x86: a cached dirty translation writes without setting the bit again.
            if (cleared)
                _gate.ShootDownGuestTlbs();
            return WriteWatchStatus.Ok;
        }
    }
}
