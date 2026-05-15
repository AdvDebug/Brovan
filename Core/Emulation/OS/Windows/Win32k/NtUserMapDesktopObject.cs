using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMapDesktopObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);

            ulong ClientAddress = Instance.WinHelper.GetUserWindowClientAddress(Window);
            Instance.SetRawSyscallReturn(ClientAddress);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
