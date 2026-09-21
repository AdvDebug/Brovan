using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserLockWindowUpdate : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            bool Locked = Win32kHelper.LockWindowUpdate(Instance, Hwnd);

            Instance.SetLastWinError(Locked ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Locked);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
