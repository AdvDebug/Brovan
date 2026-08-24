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
    /// The audio engine and the GUI thread both produce, so the counter is atomic. It only ever counts up: a
    /// missed bump costs latency until the fallback sweep, a spurious one costs a single scan.
    /// </remarks>
    public sealed class WakeSignal
    {
        private long Counter;

        public long Current => Volatile.Read(ref Counter);

        public void Bump()
        {
            Interlocked.Increment(ref Counter);
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
        public ulong CS, DS, ES, FS, GS, SS;
        public ulong DR0, DR1, DR2, DR3, DR6, DR7;
        public readonly ulong[] Xmm = new ulong[32];
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