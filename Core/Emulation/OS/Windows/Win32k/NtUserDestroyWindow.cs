using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDestroyWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            bool Success = Instance.WinHelper.DestroyWindow(Hwnd);

            Instance.SetLastWinError(Success ? 0u : ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Success);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}