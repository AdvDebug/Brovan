using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserKillTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong TimerId = Instance.WinHelper.GetArg(1);

            bool Killed = Win32kHelper.KillTimer(Instance, Hwnd, TimerId);

            Instance.SetLastWinError(Killed ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetBooleanSyscallReturn(Killed);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
