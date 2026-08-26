using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDefSetText : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong TextPtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.Title = TextPtr == 0 ? string.Empty : Win32kHelper.ReadLargeString(Instance, TextPtr) ?? string.Empty;
            Instance.WinHelper.MaterializeUserWindow(Window);
            Win32kHelper.InvalidateWindow(Instance, Hwnd);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
