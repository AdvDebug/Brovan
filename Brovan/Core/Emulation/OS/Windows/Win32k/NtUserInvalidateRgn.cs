using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserInvalidateRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Region = Instance.WinHelper.GetArg(1);
            bool Erase = Instance.WinHelper.GetArg32(2) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            List<GdiClipRect> Area = Win32kHelper.GetRedrawArea(Instance);
            bool HasArea = Region != 0 && Win32kHelper.TryReadRegion(Instance, Region, Area);
            Win32kHelper.RedrawWindow(Instance, Window, HasArea ? Area : null,
                Win32kHelper.RDW_INVALIDATE | (Erase ? Win32kHelper.RDW_ERASE : 0));

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
