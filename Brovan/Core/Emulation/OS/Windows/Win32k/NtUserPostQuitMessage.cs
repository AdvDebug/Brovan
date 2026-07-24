using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserPostQuitMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ExitCode = Instance.WinHelper.GetArg(0);

            Win32kHelper.PostQuitMessage(Instance, ExitCode);
            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}