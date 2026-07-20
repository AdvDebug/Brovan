using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForAlertByThreadId : IWinSyscall
    {
        private readonly struct AlertWaitTimeout
        {
            public AlertWaitTimeout(bool Infinite, bool PollOnly, long Deadline)
            {
                this.Infinite = Infinite;
                this.PollOnly = PollOnly;
                this.Deadline = Deadline;
            }

            public bool Infinite { get; }
            public bool PollOnly { get; }
            public long Deadline { get; }
        }

        private static AlertWaitTimeout ParseTimeout(BinaryEmulator Instance, ulong TimeoutPtr)
        {
            if (TimeoutPtr == 0)
                return new AlertWaitTimeout(true, false, -1);

            long Deadline = Instance.WinHelper.ParseRelativeDeadlineMs(TimeoutPtr);
            if (Deadline == Instance.EmulatedTickCount64)
                return new AlertWaitTimeout(false, true, -1);

            return new AlertWaitTimeout(false, false, Deadline);
        }

        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (!State.AlertByThreadIdWaitActive)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                Instance.WinHelper.ClearWaitState(Thread, true);
                return NTSTATUS.STATUS_TIMEOUT;
            }

            if (State.AlertByThreadIdPending)
            {
                State.AlertByThreadIdPending = false;
                Instance.WinHelper.ClearWaitState(Thread, true);
                return NTSTATUS.STATUS_ALERTED;
            }

            Thread.State = EmulatedThreadState.Waiting;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Address = Instance.WinHelper.GetArg(0);
            ulong TimeoutPtr = Instance.WinHelper.GetArg(1);

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitCompleted)
            {
                NTSTATUS Status = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (Thread.WaitActive)
                return ContinueWait(Instance, Thread);

            if (State.AlertByThreadIdPending)
            {
                State.AlertByThreadIdPending = false;
                return NTSTATUS.STATUS_ALERTED;
            }

            AlertWaitTimeout Timeout = ParseTimeout(Instance, TimeoutPtr);
            if (Timeout.PollOnly)
            {
                Instance._emulator.StopEmulation();
                return NTSTATUS.STATUS_TIMEOUT;
            }

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Thread, false);
            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = Timeout.Infinite ? -1 : Timeout.Deadline;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = SyscallRip;
            State.WaitReturnRIP = SyscallRip + 2;
            State.WaitAlertable = false;
            State.ApcAlertable = false;
            State.AlertByThreadIdWaitActive = true;
            State.AlertByThreadIdAddress = Address;

            Thread.State = EmulatedThreadState.Waiting;
            Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
