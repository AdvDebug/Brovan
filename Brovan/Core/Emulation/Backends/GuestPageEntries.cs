namespace Brovan.Core.Emulation
{
    internal enum GuestAccess
    {
        Read,
        Write,
        Fetch,
    }

    internal static class GuestPageEntries
    {
        public const ulong Present = 1UL << 0;
        public const ulong Writable = 1UL << 1;
        public const ulong User = 1UL << 2;
        public const ulong Accessed = 1UL << 5;
        public const ulong Dirty = 1UL << 6;
        public const ulong LargePage = 1UL << 7;
        public const ulong NoExecute = 1UL << 63;
        public const ulong AddressMask = 0x000FFFFFFFFFF000UL;

        public const ulong FaultPresent = 1UL << 0;
        public const ulong FaultWrite = 1UL << 1;
        public const ulong FaultFetch = 1UL << 4;

        public static ulong Leaf(ulong pageBase, bool present, bool writable, bool executable, ulong internalBase)
        {
            if (!present)
                return 0;

            ulong entry = pageBase | Present;
            if (writable)
                entry |= Writable;

            if (pageBase < internalBase)
                entry |= User;
            else if (!executable)
                entry |= NoExecute;

            return entry;
        }

        // A processor may still cache the old entry, so the caller flushes every processor before it returns.
        public static bool RemovesAccess(ulong oldEntry, ulong newEntry)
            => (oldEntry & ~newEntry & (Present | Writable)) != 0;

        // The leaf cannot express execute-only or write-only, so any permission reads and fetches.
        public static bool Allows(bool readable, bool writable, bool executable, GuestAccess access)
            => access == GuestAccess.Write ? writable : readable || writable || executable;

        // A present read or fetch fault would fault again, so only a not-present or write fault can be stale.
        public static bool IsStaleFault(ulong errorCode, bool readable, bool writable, bool executable)
        {
            bool write = (errorCode & FaultWrite) != 0;
            if ((errorCode & FaultPresent) != 0 && !write)
                return false;

            GuestAccess access = write ? GuestAccess.Write : (errorCode & FaultFetch) != 0 ? GuestAccess.Fetch : GuestAccess.Read;
            return Allows(readable, writable, executable, access);
        }
    }
}
