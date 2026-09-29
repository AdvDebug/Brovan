using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // A layered window that SetLayeredWindowAttributes never touched answers FALSE with no error set.
    internal class NtUserGetLayeredWindowAttributes : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong ColorKeyPtr = Instance.WinHelper.GetArg(1);
            ulong AlphaPtr = Instance.WinHelper.GetArg(2);
            ulong FlagsPtr = Instance.WinHelper.GetArg(3);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Window.LayeredByUpdate || (Window.ExStyle & Win32kHelper.WindowExStyleLayered) == 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Window.LayeredByAttributes)
            {
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if ((ColorKeyPtr != 0 && !Instance._emulator.WriteMemory(ColorKeyPtr, Window.LayeredColorKey, 4))
                || (AlphaPtr != 0 && !Instance._emulator.WriteMemory(AlphaPtr, Window.LayeredAlpha, 1))
                || (FlagsPtr != 0 && !Instance._emulator.WriteMemory(FlagsPtr, Window.LayeredFlags & 3, 4)))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_NOACCESS);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
