namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetProp2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong NamePtr = Instance.WinHelper.GetArg(1);
            ulong Data = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WinHelper.TryReadUnicodeString(NamePtr, out string Name, out _) || string.IsNullOrEmpty(Name))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.StringProperties[Name] = Data;
            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
