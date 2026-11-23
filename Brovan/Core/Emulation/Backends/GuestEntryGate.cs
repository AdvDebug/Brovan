using System;
using System.Threading;

namespace Brovan.Core.Emulation
{
    internal class GuestProcessor
    {
        // Odd while the processor is in the guest. Only the gate writes it.
        public long EntrySequence;
        public long TlbGeneration;
        public bool TlbFlushPending;
    }

    internal static class SequenceSnapshot
    {
        // A sequence is odd while its owner is inside, so an owner seen inside has left once the sequence moves.
        public static bool Passed(long seen, long now) => (seen & 1) == 0 || now != seen;
    }

    public sealed class QuiescenceSnapshot
    {
        internal readonly object Source;
        internal readonly long[] Seen;

        internal QuiescenceSnapshot(object source, long[] seen)
        {
            Source = source;
            Seen = seen;
        }
    }

    internal interface IGuestEntryBackend
    {
        // A snapshot that the binding replaces when it adds a processor.
        GuestProcessor[] Processors { get; }

        // Ends the processor's run in progress, or its next run if it has not entered yet.
        void Kick(GuestProcessor processor);
    }

    public sealed class ProcessorHold : IDisposable
    {
        public static readonly ProcessorHold None = new(null);

        private readonly GuestEntryGate? _gate;
        private int _ended;

        internal ProcessorHold(GuestEntryGate? gate) => _gate = gate;

        public void Dispose()
        {
            if (_gate != null && Interlocked.Exchange(ref _ended, 1) == 0)
                _gate.EndHold();
        }
    }

    internal sealed class GuestEntryGate : IDisposable
    {
        private readonly IGuestEntryBackend _backend;
        private readonly object _holdSync = new();
        private readonly ManualResetEventSlim _holdsEnded = new(true);
        private IBackendHost? _host;
        private RankedLock? _runLock;
        private long _tlbGeneration;
        private int _holds;

        public GuestEntryGate(IGuestEntryBackend backend) => _backend = backend;

        public void UseHost(IBackendHost host)
        {
            _host = host;
            _runLock = host.RunLock;
        }

        public bool HoldsRunLock => _runLock != null && _runLock.IsHeld;

        // On false the processor has not entered, the hold has ended and the run lock is held again.
        public bool TryEnterGuest(GuestProcessor processor, bool releaseRunLock)
        {
            if (releaseRunLock)
                _runLock!.Exit();

            // The mark goes up before the hold and TLB checks, and an evictor changes those before it reads the marks,
            // so neither misses the other.
            Interlocked.Increment(ref processor.EntrySequence);
            if (Volatile.Read(ref _holds) == 0 && processor.TlbGeneration == Volatile.Read(ref _tlbGeneration))
            {
                _host?.EnteringGuest();
                return true;
            }

            Volatile.Write(ref processor.EntrySequence, processor.EntrySequence + 1);
            while (Volatile.Read(ref _holds) != 0)
                _holdsEnded.Wait();

            if (releaseRunLock)
                _runLock!.Enter();
            return false;
        }

        public void LeaveGuest(GuestProcessor processor, bool releaseRunLock)
        {
            _host?.LeftGuest();
            Volatile.Write(ref processor.EntrySequence, processor.EntrySequence + 1);
            if (releaseRunLock)
                _runLock!.Enter();
        }

        public bool NeedsTlbFlush(GuestProcessor processor, out long generation)
        {
            generation = Volatile.Read(ref _tlbGeneration);
            return processor.TlbFlushPending || processor.TlbGeneration != generation;
        }

        public static void TlbFlushed(GuestProcessor processor, long generation)
        {
            processor.TlbFlushPending = false;
            processor.TlbGeneration = generation;
        }

        // NT flushes every processor before a protect that removes access returns.
        public void ShootDownGuestTlbs()
        {
            Interlocked.Increment(ref _tlbGeneration);
            EvictProcessors();
        }

        // What the caller made unreachable before the call stays unreachable for a processor that enters after it.
        public void EvictProcessors()
        {
            Interlocked.MemoryBarrier();
            GuestProcessor[] processors = _backend.Processors;
            Span<long> seen = processors.Length <= 256 ? stackalloc long[processors.Length] : new long[processors.Length];
            bool kicked = false;
            for (int i = 0; i < processors.Length; i++)
            {
                seen[i] = Volatile.Read(ref processors[i].EntrySequence);
                if ((seen[i] & 1) == 0)
                    continue;

                _backend.Kick(processors[i]);
                kicked = true;
            }

            if (!kicked)
                return;

            for (int i = 0; i < processors.Length; i++)
            {
                SpinWait spin = default;
                while (!SequenceSnapshot.Passed(seen[i], Volatile.Read(ref processors[i].EntrySequence)))
                    spin.SpinOnce(-1);
            }
        }

        public ProcessorHold HoldProcessorsOutOfGuest()
        {
            lock (_holdSync)
            {
                if (_holds++ == 0)
                    _holdsEnded.Reset();
            }

            EvictProcessors();
            return new ProcessorHold(this);
        }

        internal void EndHold()
        {
            lock (_holdSync)
            {
                if (--_holds == 0)
                    _holdsEnded.Set();
            }
        }

        public void Dispose() => _holdsEnded.Dispose();
    }
}
