namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRemoveProp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Key = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            ushort Atom = (ushort)Key;
            Window.AtomProperties.Remove(Atom, out ulong Previous);

            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
