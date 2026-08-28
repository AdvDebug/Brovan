namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetProp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            // Bit 16 tells win32k the atom came from a string and owns an atom reference; the key is the low word.
            ulong Key = Instance.WinHelper.GetArg(1);
            ulong Data = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.AtomProperties[(ushort)Key] = Data;
            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
