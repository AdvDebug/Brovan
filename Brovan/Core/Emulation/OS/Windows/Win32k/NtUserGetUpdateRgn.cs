using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetUpdateRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Region = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            List<GdiClipRect> Rects = Win32kHelper.GetRedrawArea(Instance);
            if (Window.PaintPending)
                Win32kHelper.GetUpdateRegion(Instance, Window, Rects);

            int Type = Win32kHelper.WriteRegion(Instance, Region, Rects);
            if (Type == Win32kHelper.RegionError)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn(Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)Type);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
