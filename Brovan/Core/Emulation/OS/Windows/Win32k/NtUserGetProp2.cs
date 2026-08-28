namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetProp2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong NamePtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // The value is the syscall return, so a failure must read as a missing property, never as a status.
            ulong Result = 0;
            if (Instance.WinHelper.TryReadUnicodeString(NamePtr, out string Name, out _) && !string.IsNullOrEmpty(Name))
                Window.StringProperties.TryGetValue(Name, out Result);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
