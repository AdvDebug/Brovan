using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, Hwnd, false, false);
            Instance.SetLastWinError(Hdc == 0 ? Win32kHelper.ERROR_INVALID_WINDOW_HANDLE : 0u);
            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
