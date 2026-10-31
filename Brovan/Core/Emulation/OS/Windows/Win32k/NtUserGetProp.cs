using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetProp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ushort Atom = (ushort)Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            Window.AtomProperties.TryGetValue(Atom, out ulong Result);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
