using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserValidateHandleSecure : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            Instance.SetRawSyscallReturn(Instance.WinHelper.GetWindow(Hwnd) != null ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
