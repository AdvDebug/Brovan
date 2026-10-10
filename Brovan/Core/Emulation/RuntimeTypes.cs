using System;
using System.Collections.Generic;
using System.Threading;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Counts the state changes that can make a blocked guest thread runnable. The scheduler compares it against
    /// the value it last scanned at, so a slice that produced nothing skips the wakeup scan entirely.
    /// </summary>
    /// <remarks>
    /// The audio engine, the GUI thread and the host socket threads produce, so the counter is atomic. It only
    /// ever counts up: a missed bump costs latency until the fallback sweep, a spurious one costs a single scan.
    /// </remarks>
    public sealed class WakeSignal
    {
        [ThreadStatic]
        private static WakeSignal t_served;

        private long Counter;
        private long HostCounter;
        private int Sleeping;
        private readonly ManualResetEventSlim Gate = new(false);

        public long Current => Volatile.Read(ref Counter);

        // Counts only bumps from threads that did not call BeginServing.
        public long HostCurrent => Volatile.Read(ref HostCounter);

        public long Bump()
        {
            long Epoch = Interlocked.Increment(ref Counter);
            if (!ReferenceEquals(t_served, this))
                Interlocked.Increment(ref HostCounter);
            if (Volatile.Read(ref Sleeping) != 0)
                Gate.Set();

            return Epoch;
        }

        public void BeginServing() => t_served = this;

        public void EndServing()
        {
            if (ReferenceEquals(t_served, this))
                t_served = null;
        }

        // One waiter at a time. False when the counter had already moved.
        public bool WaitPast(long Observed, int Milliseconds) => WaitWhileUnchanged(ref Counter, Observed, Milliseconds);

        public bool WaitPastHost(long ObservedHost, int Milliseconds) => WaitWhileUnchanged(ref HostCounter, ObservedHost, Milliseconds);

        private bool WaitWhileUnchanged(ref long Count, long Observed, int Milliseconds)
        {
            Gate.Reset();
            Interlocked.Exchange(ref Sleeping, 1);
            bool Waits = Volatile.Read(ref Count) == Observed;
            if (Waits)
                Gate.Wait(Milliseconds);

            Volatile.Write(ref Sleeping, 0);
            return Waits;
        }
    }

    public sealed class CpuContext
    {
        public ulong RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong RIP;
        public ulong RFLAGS;
        public ulong MXCSR = 0x1F80;
        public ulong FPCW = 0x027F;
        public ulong FPSW;
        public ulong FPTAG = 0xFFFF;
        public ulong CS, DS, ES, FS, GS, SS;
        public ulong DR0, DR1, DR2, DR3, DR6, DR7;
        public readonly ulong[] Xmm = new ulong[32];
        public readonly ulong[] YmmHigh = new ulong[32];
        public readonly ulong[] X87 = new ulong[16];
    }

    public enum EmulatedThreadState
    {
        Ready,
        Running,
        Waiting,
        Suspended,
        Terminated,
        Exception
    }

    public partial class EmulatedThread
    {
        public uint ThreadId;
        public string Name;

        public ulong StackAddress;
        public ulong StackSize;
        public ulong StackLimit;

        public ulong StartAddress;
        public ulong Parameter;
        public EmulatedThreadState State;

        public int BasePriority = 8;
        public int DynamicBoost;
        public int QueueLevel;
        public ulong AffinityMask = ulong.MaxValue;
        public bool DisablePriorityBoost;
        public long LastReadyTick;
        public long LastRunTick = -1;
        public int HostWorker = -1;
        public bool ParkWaiting;
        public EmulatedThread ParkTarget;
        public bool Unreferenced;

        // Follows the order of BinaryEmulator.ThreadOrder.
        internal long OrderKey;
        internal bool InWakeScanList;

        public int EffectivePriority
        {
            get
            {
                int priority = BasePriority + DynamicBoost;
                if (priority < 0) return 0;
                if (priority > 31) return 31;
                return priority;
            }
        }

        public CpuContext Context;
        public ulong LastRIP;
        public ulong InstructionsExecuted;
        public long RunTicks;
        public int ExitCode;
        public int SuspendCount;
        public bool WaitActive;
        public List<ulong> WaitHandles;
        public bool WaitAll;
        public long WaitDeadline;
        public bool WaitTimedOut;
        public int WaitSatisfiedIndex = -1;
        public bool SwitchingContext;
        public object GuestState { get; set; }

        public void SwitchContext(BinaryEmulator emulator)
        {
            if (emulator == null)
                throw new InvalidOperationException(nameof(emulator));

            if (Context == null)
                Context = new CpuContext();

            if (State == EmulatedThreadState.Running)
            {
                emulator.ReadGprBatch(Context);
                return;
            }

            emulator.WriteGprBatch(Context);
            SwitchingContext = true;
        }
    }
}