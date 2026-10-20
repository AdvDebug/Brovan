using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserScheduleDispatchNotification : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            if (Instance.WinHelper.GetWindow(Hwnd) == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            Win32kHelper.PostEventNotification(Instance, Hwnd, Win32kQueuePort.DispatchMessage, 0, 0);
            Instance.SetRawSyscallReturn(2);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
