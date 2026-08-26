using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDestroyCaret : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Destroyed = Win32kHelper.DestroyCaret(Instance);
            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(Destroyed);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
