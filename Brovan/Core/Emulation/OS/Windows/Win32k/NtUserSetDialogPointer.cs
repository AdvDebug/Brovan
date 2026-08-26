using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetDialogPointer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Dialog = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // The cbWndExtra block is the application's, and its first slots are the DWLP_ indexes.
            Window.DialogPointer = Dialog;
            Window.IsDialog = Dialog != 0;
            Window.Dirty = true;
            Instance.WinHelper.MaterializeUserWindow(Window);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
