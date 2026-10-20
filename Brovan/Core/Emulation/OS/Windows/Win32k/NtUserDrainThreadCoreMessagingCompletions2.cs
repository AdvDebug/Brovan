using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDrainThreadCoreMessagingCompletions2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            if (Instance.WinHelper.GetWindow(Hwnd) == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            WindowsThreadState State = WinEmulatedThread.GetState(Instance.CurrentThread);
            if (!Win32kQueuePort.HasCoreMessagingWindow(State))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_ACCESS_DENIED);

            int Slot = Win32kQueuePort.GetSlot(State, Hwnd);
            if (Slot < 0)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Win32kQueuePort.Drain(Instance, State, (ulong)Slot);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
