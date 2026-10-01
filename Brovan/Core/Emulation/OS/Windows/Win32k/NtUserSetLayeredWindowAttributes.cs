using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetLayeredWindowAttributes : IWinSyscall
    {
        private const uint ValidFlags = 0x00000003;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint ColorKey = (uint)Instance.WinHelper.GetArg(1);
            byte Alpha = (byte)Instance.WinHelper.GetArg(2);
            uint Flags = (uint)Instance.WinHelper.GetArg(3);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            if ((Flags & ~ValidFlags) != 0 || (Window.ExStyle & Win32kHelper.WindowExStyleLayered) == 0)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            // NT: works on a window layered by UpdateLayeredWindow.
            Window.LayeredByUpdate = false;
            Window.LayeredByAttributes = true;
            Window.LayeredColorKey = ColorKey;
            Window.LayeredAlpha = Alpha;
            Window.LayeredFlags = Flags;

            Instance.WinHelper.PresentDesktop();

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
