using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserValidateHandleSecure : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            Instance.SetRawSyscallReturn(Instance.WinHelper.GetWindow(Hwnd) != null ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
