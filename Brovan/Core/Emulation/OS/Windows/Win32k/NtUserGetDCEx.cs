using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDCEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong HdcClipRegion = Instance.WinHelper.GetArg(1);
            uint Flags = (uint)Instance.WinHelper.GetArg(2);

            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, Hwnd, false, false);
            Instance.SetLastWinError(Hdc == 0 ? Win32kHelper.ERROR_INVALID_WINDOW_HANDLE : 0u);
            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
