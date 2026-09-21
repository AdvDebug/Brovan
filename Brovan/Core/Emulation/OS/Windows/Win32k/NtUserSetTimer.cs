using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong TimerId = Instance.WinHelper.GetArg(1);
            uint Elapse = (uint)Instance.WinHelper.GetArg(2);
            ulong TimerProc = Instance.WinHelper.GetArg(3);

            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetRawSyscallReturn(Win32kHelper.SetTimer(Instance, Hwnd, TimerId, Elapse, TimerProc));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
