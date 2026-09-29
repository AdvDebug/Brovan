using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserValidateRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            // NT: with no window this redraws the composed desktop, which changes no window.
            if (Hwnd == 0)
            {
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            List<GdiClipRect> Area = Win32kHelper.GetRedrawArea(Instance);
            if (Window == null || (RectPtr != 0 && !Win32kHelper.TryReadGuestRect(Instance, RectPtr, Area)))
            {
                Instance.SetLastWinError(Window == null ? Win32kHelper.ERROR_INVALID_WINDOW_HANDLE : Win32kHelper.ERROR_NOACCESS);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.RedrawWindow(Instance, Window, RectPtr != 0 ? Area : null, Win32kHelper.RDW_VALIDATE);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
