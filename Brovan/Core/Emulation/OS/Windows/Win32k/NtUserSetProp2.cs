namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetProp2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong NamePtr = Instance.WinHelper.GetArg(1);
            ulong Data = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            if (!Instance.WinHelper.TryReadUnicodeString(NamePtr, out string Name, out _) || string.IsNullOrEmpty(Name))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ushort Atom = Instance.WinHelper.RegisterWindowMessageAtom(Name);
            if (Atom == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.AtomProperties[Atom] = Data;
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
