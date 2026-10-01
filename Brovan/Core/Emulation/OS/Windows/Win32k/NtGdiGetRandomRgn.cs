using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetRandomRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong Region = Instance.WinHelper.GetArg(1);
            int Code = unchecked((int)Instance.WinHelper.GetArg(2));

            int Result = Win32kHelper.GetDcRandomRegion(Instance, Hdc, Region, Code);
            Instance.SetLastWinError(Result < 0 ? Win32kHelper.ERROR_INVALID_PARAMETER : 0u);
            Instance.SetRawSyscallReturn(unchecked((ulong)(long)Result));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
