namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryWnfStateData : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
