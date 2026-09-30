using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetUpdateRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            bool Pending = Win32kHelper.GetUpdateRect(Instance, Window, out GdiClipRect Update);

            if (RectPtr != 0)
            {
                if (!Instance.IsRegionMapped(RectPtr, Win32kHelper.GuestRectSize))
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                if (!Win32kHelper.TryWriteGuestRect(Instance, RectPtr, Update))
                {
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(Pending);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
