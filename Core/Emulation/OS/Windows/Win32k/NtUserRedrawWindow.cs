using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRedrawWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong RectPtr = Instance.WinHelper.GetArg64(1);
            ulong Region = Instance.WinHelper.GetArg64(2);
            uint Flags = (uint)Instance.WinHelper.GetArg64(3, true);

            bool Success = Win32kHelper.InvalidateWindow(Instance, Hwnd);
            Instance.SetLastWinError(Success ? 0u : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Success);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
