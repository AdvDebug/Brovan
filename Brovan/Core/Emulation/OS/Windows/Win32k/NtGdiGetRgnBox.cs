using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetRgnBox : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Region = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            Win32kHelper.GetRegionScratch(Instance, out List<GdiClipRect> Rects, out _, out _);
            if (RectPtr == 0 || !Win32kHelper.TryReadRegion(Instance, Region, Rects))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.GetRegionBounds(Rects, out GdiClipRect Box);
            if (!Win32kHelper.TryWriteGuestRect(Instance, RectPtr, Box))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn((ulong)Win32kHelper.GetRegionType(Rects));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
