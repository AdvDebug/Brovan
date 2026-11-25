using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForAlertByThreadId : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Scheduler;

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

        private static AlertWaitTimeout ParseTimeout(BinaryEmulator Instance, long? Timeout)
        {
            if (Timeout == null)
                return new AlertWaitTimeout(true, false, -1);

            long Deadline = Instance.WinHelper.ParseRelativeDeadlineMs(Timeout);
            if (Deadline == Instance.EmulatedTickCount64)
                return new AlertWaitTimeout(false, true, -1);

            return new AlertWaitTimeout(false, false, Deadline);
        }

        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitKind != WindowsWaitKind.Alert)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                return NTSTATUS.STATUS_TIMEOUT;
            }

            if (State.AlertByThreadIdPending)
            {
                State.AlertByThreadIdPending = false;
                Instance.WinHelper.ClearWaitState(Thread);
                return NTSTATUS.STATUS_ALERTED;
            }

            return Instance.WinHelper.ContinueParked(Thread);
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

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? CapturedTimeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (State.AlertByThreadIdPending)
            {
                State.AlertByThreadIdPending = false;
                return NTSTATUS.STATUS_ALERTED;
            }

            AlertWaitTimeout Timeout = ParseTimeout(Instance, CapturedTimeout);
            if (Timeout.PollOnly)
            {
                Instance._emulator.StopEmulation();
                return NTSTATUS.STATUS_TIMEOUT;
            }

            State.AlertByThreadIdAddress = Address;
            return Instance.WinHelper.ParkUntil(Thread, Timeout.Infinite ? -1 : Timeout.Deadline, false, WindowsWaitKind.Alert);
        }
    }
}
