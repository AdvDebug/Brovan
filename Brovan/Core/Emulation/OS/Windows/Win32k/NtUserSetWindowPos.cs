using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowPos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Win32kHelper.Win32kDeferredWindowPos Position = new Win32kHelper.Win32kDeferredWindowPos
            {
                Hwnd = Instance.WinHelper.GetArg(0),
                InsertAfter = Instance.WinHelper.GetArg(1),
                X = unchecked((int)Instance.WinHelper.GetArg(2)),
                Y = unchecked((int)Instance.WinHelper.GetArg(3)),
                Width = unchecked((int)Instance.WinHelper.GetArg(4)),
                Height = unchecked((int)Instance.WinHelper.GetArg(5)),
                Flags = (uint)Instance.WinHelper.GetArg(6),
            };

            Instance.SetLastWinError(0);
            if (Win32kHelper.SendWindowPos(Instance, Position, out bool Success))
                return NTSTATUS.STATUS_SUCCESS;

            if (!Success)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
