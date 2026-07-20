using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetForegroundWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.SetRawSyscallReturn(Instance.WinHelper.GetForegroundWindow());
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}