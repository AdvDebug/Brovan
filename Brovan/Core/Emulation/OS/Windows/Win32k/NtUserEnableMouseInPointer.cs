using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnableMouseInPointer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Win32kHelper.SetMouseInPointer(Instance, Instance.WinHelper.GetArg(0) != 0);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
