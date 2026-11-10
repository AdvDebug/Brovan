namespace Brovan.Core.Emulation.OS.Windows
{
    internal enum SessionIdKind
    {
        Luid,
        PackageHost,
        AlpcChannel,

        // OXIDs and OIDs that RPCSS gives.
        ObjectExporter,
    }

    internal static unsafe class SessionIds
    {
        private const string FileName = "ids.bin";
        private const int CellStride = 64;

        // The value sits above the fixed LUIDs and the interactive logon ids of WinToken.
        internal const ulong FirstLuid = 0x100000;

        private const int FallbackShift = 32;

        private readonly record struct Kind(ulong First, ulong FixedBits);

        private static readonly Kind[] Kinds =
        {
            new Kind(FirstLuid, 0),
            new Kind(1, 0x1000000000000000),
            new Kind(1, 0),
            new Kind(0x1000, 0),
        };

        private static readonly object Sync = new();
        private static readonly ulong[] Fallback = new ulong[Kinds.Length];
        private static SessionMapping _cells;
        private static bool _unavailable;
        private static bool _closed;

        internal static ulong Next(SessionIdKind Which)
        {
            Kind Info = Kinds[(int)Which];

            // GuestSession.OpenDirectory takes GuestSession's lock, so it runs before this class takes its own.
            string Directory = null;
            if (Volatile.Read(ref _cells) == null && !Volatile.Read(ref _closed) && !Volatile.Read(ref _unavailable))
                Directory = GuestSession.OpenDirectory;

            lock (Sync)
            {
                if (_cells == null && Directory != null && !_closed && !_unavailable)
                {
                    _cells = SessionMapping.OpenFile(Path.Combine(Directory, FileName), FileMode.OpenOrCreate, Kinds.Length * CellStride);
                    _unavailable = _cells == null;
                }

                if (_cells != null)
                {
                    ulong Taken = (ulong)Interlocked.Increment(ref *(long*)(_cells.Base + (int)Which * CellStride));
                    return Info.FixedBits | (Info.First + Taken - 1);
                }

                ulong Own = Info.First + Fallback[(int)Which]++;
                return Info.FixedBits | ((ulong)(uint)Environment.ProcessId << FallbackShift) | Own;
            }
        }

        internal static void Close()
        {
            lock (Sync)
            {
                _cells?.Dispose();
                _cells = null;
                Volatile.Write(ref _closed, true);
            }
        }
    }
}
