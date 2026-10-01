using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiEqualRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong First = Instance.WinHelper.GetArg(0);
            ulong Second = Instance.WinHelper.GetArg(1);

            Win32kHelper.GetRegionScratch(Instance, out List<GdiClipRect> A, out List<GdiClipRect> B, out List<GdiClipRect> Difference);
            bool Equal = Win32kHelper.TryReadRegion(Instance, First, A)
                && Win32kHelper.TryReadRegion(Instance, Second, B)
                && Win32kHelper.CombineRegions(A, B, Win32kHelper.RgnXor, Difference)
                && Difference.Count == 0;

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Equal ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
