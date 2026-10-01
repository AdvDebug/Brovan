using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetAppClipBox : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            int Result = Win32kHelper.GetDcClipBox(Instance, Hdc, out GdiClipRect Box);
            if (Result == Win32kHelper.RegionError || RectPtr == 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryWriteGuestRect(Instance, RectPtr, Box))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
