using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnableWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            bool Enable = Instance.WinHelper.GetArg32(1) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            bool WasDisabled = (Window.Style & Win32kHelper.WindowStyleDisabled) != 0;
            bool Changed = WasDisabled == Enable;
            if (Changed)
            {
                Window.Style = Enable ? Window.Style & ~Win32kHelper.WindowStyleDisabled : Window.Style | Win32kHelper.WindowStyleDisabled;
                Instance.WinHelper.MaterializeUserWindow(Window);

                // A disabled host window passes clicks to the window it owns.
                if (Window.ParentHwnd == 0)
                    Instance.WinHelper.PresentDesktop();
            }

            // NT: xxxEnableWindow sends these before it returns.
            Win32kHelper.PostEnableNotifications(Instance, Window, Enable, Changed);

            Instance.SetLastWinError(0);
            Win32kHelper.ReturnAfterNotifications(Instance, WasDisabled ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
