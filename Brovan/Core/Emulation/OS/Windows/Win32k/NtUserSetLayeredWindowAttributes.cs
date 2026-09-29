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
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if ((Flags & ~ValidFlags) != 0 || Window.LayeredByUpdate || (Window.ExStyle & Win32kHelper.WindowExStyleLayered) == 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

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
