using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetRandomRgn : IWinSyscall
    {
        private const int RegionCodeClip = 1;
        private const int RegionCodeMeta = 2;
        private const int RegionCodeApi = 3;
        private const int RegionCodeSystem = 4;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            Instance.WinHelper.GetArg(1);
            int Code = unchecked((int)Instance.WinHelper.GetArg(2));

            if (!Win32kHelper.IsKnownDc(Instance, Hdc))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(unchecked((ulong)-1L));
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Code < RegionCodeClip || Code > RegionCodeSystem)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(unchecked((ulong)-1L));
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
