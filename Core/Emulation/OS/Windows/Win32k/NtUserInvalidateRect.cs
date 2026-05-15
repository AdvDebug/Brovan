using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserInvalidateRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong RectPtr = Instance.WinHelper.GetArg64(1);
            bool Erase = Instance.WinHelper.GetArg64(2, true) != 0;

            bool Success = Win32kHelper.InvalidateWindow(Instance, Hwnd);
            Instance.SetLastWinError(Success ? 0u : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Success);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
