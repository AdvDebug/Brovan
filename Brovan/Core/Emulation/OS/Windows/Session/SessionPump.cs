namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class SessionPump
    {
        private const string FileName = "doorbells.bin";

        // One cache line per member, so two doorbells never share a line.
        private const int DoorbellStride = 64;

        private static readonly object Sync = new();
        private static SessionMapping _doorbells;
        private static bool _unavailable;
        private static bool _closed;

        private static uint _seenDoorbell;
        private static bool _rescan;
        private static WakeSignal _wake;

        // Ring only after the work is published. Any thread may ring, also one that does not hold KernelLock.
        internal static void Ring(int Slot)
        {
            if ((uint)Slot >= GuestSession.SlotCount)
                return;

            lock (Sync)
            {
                if (TryOpen())
                    Interlocked.Increment(ref *(int*)Doorbell(Slot));
            }

            // A ring of this process's own slot comes from one of its host threads, and an idle scheduler wakes for it.
            if (Slot == GuestSession.OwnSlot)
                Volatile.Read(ref _wake)?.Bump();
        }

        internal static void Run(BinaryEmulator Instance)
        {
            int Slot = GuestSession.OwnSlot;
            if (Slot < 0)
                return;

            Volatile.Write(ref _wake, Instance.WakeSignal);

            lock (Sync)
            {
                // Without its doorbell the member still serves every pass what other processes leave for it.
                if (_doorbells != null)
                {
                    uint Value = Volatile.Read(ref *(uint*)Doorbell(Slot));
                    if (!_rescan && Value == _seenDoorbell)
                        return;

                    _seenDoorbell = Value;
                }
                else if (!_unavailable)
                {
                    return;
                }
            }

            _rescan = false;

            RemoteProcessRequests.Drain(Instance);
            AlpcMessaging.DrainRemote(Instance);
        }

        // Only for a consumer that runs on the scheduler pass. Any other thread rings the slot of this process instead.
        internal static void Rescan() => _rescan = true;

        // The caller holds the session lock.
        internal static void Reset(int Slot)
        {
            lock (Sync)
            {
                if (TryOpen())
                    Volatile.Write(ref *(uint*)Doorbell(Slot), 0);

                _seenDoorbell = 0;
                _rescan = false;
            }
        }

        internal static void Close()
        {
            lock (Sync)
            {
                _doorbells?.Dispose();
                _doorbells = null;
                _closed = true;
            }
        }

        private static byte* Doorbell(int Slot) => _doorbells.Base + (long)Slot * DoorbellStride;

        private static bool TryOpen()
        {
            if (_doorbells != null)
                return true;

            if (_unavailable || _closed)
                return false;

            _doorbells = SessionMapping.OpenFile(Path.Combine(GuestSession.Directory, FileName), FileMode.OpenOrCreate,
                (long)GuestSession.SlotCount * DoorbellStride);
            _unavailable = _doorbells == null;
            return _doorbells != null;
        }
    }
}
