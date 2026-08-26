using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Brovan runs one monitor, so both windows already share it.
    internal class NtUserInheritWindowMonitor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong SourceHwnd = Instance.WinHelper.GetArg(1);

            bool Valid = Instance.WinHelper.GetWindow(Hwnd) != null &&
                (SourceHwnd == 0 || Instance.WinHelper.GetWindow(SourceHwnd) != null);

            Instance.SetLastWinError(Valid ? 0u : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Valid);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
