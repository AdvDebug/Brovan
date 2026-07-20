using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForSingleObject : IWinSyscall
    {
        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread.WaitHandles != null && Thread.WaitHandles.Count > 0 && Instance.TryAcquireWaitHandle(Thread.WaitHandles[0], Thread, out NTSTATUS AcquiredStatus))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                return AcquiredStatus;
            }

            if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                return NTSTATUS.STATUS_TIMEOUT;
            }

            Thread.State = EmulatedThreadState.Waiting;
            WinEmulatedThread.GetState(Thread).ApcAlertable = WinEmulatedThread.GetState(Thread).WaitAlertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Handle = Instance.WinHelper.GetArg(0);
            bool Alertable = (uint)Instance.WinHelper.GetArg(1) != 0;
            ulong TimeoutPtr = Instance.WinHelper.GetArg(2);

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (WinEmulatedThread.GetState(Thread).WaitCompleted)
            {
                NTSTATUS Status = WinEmulatedThread.GetState(Thread).WaitStatus;
                WinEmulatedThread.GetState(Thread).WaitCompleted = false;
                WinEmulatedThread.GetState(Thread).WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (Thread.WaitActive)
                return ContinueWait(Instance, Thread);

            IHandleObject Obj = Instance.WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (Obj == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Instance.TryAcquireWaitHandle(Handle, Thread, out NTSTATUS AcquiredStatus))
                return AcquiredStatus;

            long Deadline = Instance.WinHelper.ParseRelativeDeadlineMs(TimeoutPtr);
            if (Deadline == Instance.EmulatedTickCount64)
                return NTSTATUS.STATUS_TIMEOUT;

            Thread.WaitActive = true;
            Thread.WaitHandles = new List<ulong> { Handle };
            Thread.WaitAll = true;
            Thread.WaitDeadline = Deadline;
            WinEmulatedThread.GetState(Thread).WaitCompleted = false;
            WinEmulatedThread.GetState(Thread).WaitStatus = NTSTATUS.STATUS_PENDING;
            WinEmulatedThread.GetState(Thread).WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
            WinEmulatedThread.GetState(Thread).WaitReturnRIP = WinEmulatedThread.GetState(Thread).WaitResumeRIP + 2;
            WinEmulatedThread.GetState(Thread).WaitAlertable = Alertable;

            Thread.State = EmulatedThreadState.Waiting;
            WinEmulatedThread.GetState(Thread).ApcAlertable = Alertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_PENDING;
        }
    }
}
