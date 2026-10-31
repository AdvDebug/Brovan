namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetProp2 : IWinSyscall
    {
        private const uint ERROR_FILE_NOT_FOUND = 2;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong NamePtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            // The value is the syscall return, so a failure must read as a missing property, never as a status.
            ulong Result = 0;
            if (Instance.WinHelper.TryReadUnicodeString(NamePtr, out string Name, out _) && !string.IsNullOrEmpty(Name))
            {
                if (Instance.WinHelper.TryFindGlobalAtom(Name, out ushort Atom))
                    Window.AtomProperties.TryGetValue(Atom, out Result);
                else
                    Instance.SetLastWinError(ERROR_FILE_NOT_FOUND);
            }

            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
