using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserWaitMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
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

            if (Win32kHelper.HasQueuedInputEvent(Instance, Win32kHelper.QS_ALLINPUT))
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Thread.WaitActive)
            {
                Thread.WaitActive = true;
                Thread.WaitHandles = null;
                Thread.WaitAll = false;
                Thread.WaitDeadline = -1;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_PENDING;
                State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
                State.WaitReturnRIP = State.WaitResumeRIP + 2;
                State.WaitAlertable = false;
                State.WaitMessageActive = true;
            }

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = false;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
