namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRemoveProp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Key = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ushort Atom = (ushort)Key;
            Window.AtomProperties.Remove(Atom, out ulong Previous);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
