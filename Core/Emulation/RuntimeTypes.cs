using System;
using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation
{
    public sealed class CpuContext
    {
        public ulong RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong RIP;
        public ulong RFLAGS;
        public ulong MXCSR;
        public ulong CS, DS, ES, FS, GS, SS;
        public ulong DR0, DR1, DR2, DR3, DR6, DR7;
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

        public ulong StartAddress;
        public ulong Parameter;
        public EmulatedThreadState State;

        public int BasePriority = 8;
        public int DynamicBoost;
        public int QueueLevel;
        public ulong AffinityMask = ulong.MaxValue;
        public bool DisablePriorityBoost;
        public int SpinWaitScore;
        public ulong LastSpinWaitRip;
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
                Context.RAX = emulator.ReadRegister(Registers.UC_X86_REG_RAX);
                Context.RBX = emulator.ReadRegister(Registers.UC_X86_REG_RBX);
                Context.RCX = emulator.ReadRegister(Registers.UC_X86_REG_RCX);
                Context.RDX = emulator.ReadRegister(Registers.UC_X86_REG_RDX);
                Context.RSI = emulator.ReadRegister(Registers.UC_X86_REG_RSI);
                Context.RDI = emulator.ReadRegister(Registers.UC_X86_REG_RDI);
                Context.RBP = emulator.ReadRegister(Registers.UC_X86_REG_RBP);
                Context.RSP = emulator.ReadRegister(Registers.UC_X86_REG_RSP);
                Context.R8 = emulator.ReadRegister(Registers.UC_X86_REG_R8);
                Context.R9 = emulator.ReadRegister(Registers.UC_X86_REG_R9);
                Context.R10 = emulator.ReadRegister(Registers.UC_X86_REG_R10);
                Context.R11 = emulator.ReadRegister(Registers.UC_X86_REG_R11);
                Context.R12 = emulator.ReadRegister(Registers.UC_X86_REG_R12);
                Context.R13 = emulator.ReadRegister(Registers.UC_X86_REG_R13);
                Context.R14 = emulator.ReadRegister(Registers.UC_X86_REG_R14);
                Context.R15 = emulator.ReadRegister(Registers.UC_X86_REG_R15);
                Context.RIP = emulator.ReadRegister(Registers.UC_X86_REG_RIP);
                Context.RFLAGS = emulator.ReadRegister(Registers.UC_X86_REG_EFLAGS);
                return;
            }

            emulator.WriteRegister(Registers.UC_X86_REG_RAX, Context.RAX);
            emulator.WriteRegister(Registers.UC_X86_REG_RBX, Context.RBX);
            emulator.WriteRegister(Registers.UC_X86_REG_RCX, Context.RCX);
            emulator.WriteRegister(Registers.UC_X86_REG_RDX, Context.RDX);
            emulator.WriteRegister(Registers.UC_X86_REG_RSI, Context.RSI);
            emulator.WriteRegister(Registers.UC_X86_REG_RDI, Context.RDI);
            emulator.WriteRegister(Registers.UC_X86_REG_RBP, Context.RBP);
            emulator.WriteRegister(Registers.UC_X86_REG_RSP, Context.RSP);
            emulator.WriteRegister(Registers.UC_X86_REG_R8, Context.R8);
            emulator.WriteRegister(Registers.UC_X86_REG_R9, Context.R9);
            emulator.WriteRegister(Registers.UC_X86_REG_R10, Context.R10);
            emulator.WriteRegister(Registers.UC_X86_REG_R11, Context.R11);
            emulator.WriteRegister(Registers.UC_X86_REG_R12, Context.R12);
            emulator.WriteRegister(Registers.UC_X86_REG_R13, Context.R13);
            emulator.WriteRegister(Registers.UC_X86_REG_R14, Context.R14);
            emulator.WriteRegister(Registers.UC_X86_REG_R15, Context.R15);
            emulator.WriteRegister(Registers.UC_X86_REG_RIP, Context.RIP);
            emulator.WriteRegister(Registers.UC_X86_REG_EFLAGS, Context.RFLAGS);
            SwitchingContext = true;
        }
    }
}