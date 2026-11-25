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

            Win32kQueuePort.TakePackets(Instance, State);
            if (Win32kHelper.HasQueuedInputEvent(Instance, Win32kHelper.QS_ALLINPUT, Thread.ThreadId))
            {
                if (Thread.WaitActive)
                    Instance.WinHelper.ClearWaitState(Thread);
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Thread.WaitActive)
                return Instance.WinHelper.ParkUntil(Thread, Win32kHelper.GetNextTimerDue(Instance, 0, Thread.ThreadId, 0, 0), false, WindowsWaitKind.WaitMessage);

            return Instance.WinHelper.ContinueParked(Thread);
        }
    }
}
