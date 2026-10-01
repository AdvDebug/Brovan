using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtSelectClipRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong Region = Instance.WinHelper.GetArg(1);
            int Mode = unchecked((int)Instance.WinHelper.GetArg(2));

            int Result = Win32kHelper.SelectDcClipRegion(Instance, Hdc, Region, Mode);
            Instance.SetLastWinError(Result == Win32kHelper.RegionError ? Win32kHelper.ERROR_INVALID_PARAMETER : 0u);
            Instance.SetRawSyscallReturn((ulong)Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
