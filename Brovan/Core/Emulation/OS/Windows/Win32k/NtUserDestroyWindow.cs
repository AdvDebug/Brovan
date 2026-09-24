using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDestroyWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);

            if (!Instance.WinHelper.DestroyWindow(Hwnd, 1, out bool Deferred))
            {
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Deferred)
                Instance.SetBooleanSyscallReturn(true);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}