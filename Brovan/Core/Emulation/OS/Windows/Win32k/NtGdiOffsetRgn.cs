using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiOffsetRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Region = Instance.WinHelper.GetArg(0);
            int OffsetX = unchecked((int)Instance.WinHelper.GetArg(1));
            int OffsetY = unchecked((int)Instance.WinHelper.GetArg(2));

            Win32kHelper.GetRegionScratch(Instance, out List<GdiClipRect> Rects, out _, out _);
            if (!Win32kHelper.TryReadRegion(Instance, Region, Rects))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (int i = 0; i < Rects.Count; i++)
                Rects[i] = Win32kHelper.ShiftRect(Rects[i], OffsetX, OffsetY);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)Win32kHelper.WriteRegion(Instance, Region, Rects));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
