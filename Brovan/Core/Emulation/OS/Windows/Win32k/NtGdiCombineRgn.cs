using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCombineRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Destination = Instance.WinHelper.GetArg(0);
            ulong SourceA = Instance.WinHelper.GetArg(1);
            ulong SourceB = Instance.WinHelper.GetArg(2);
            int Mode = unchecked((int)Instance.WinHelper.GetArg(3));

            Win32kHelper.GetRegionScratch(Instance, out List<GdiClipRect> A, out List<GdiClipRect> B, out List<GdiClipRect> Result);
            if (!Win32kHelper.TryReadRegion(Instance, SourceA, A)
                || (Mode != Win32kHelper.RgnCopy && !Win32kHelper.TryReadRegion(Instance, SourceB, B))
                || !Win32kHelper.CombineRegions(A, B, Mode, Result))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Type = Win32kHelper.WriteRegion(Instance, Destination, Result);
            Instance.SetLastWinError(Type == Win32kHelper.RegionError ? Win32kHelper.ERROR_INVALID_HANDLE : 0u);
            Instance.SetRawSyscallReturn((ulong)Type);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
