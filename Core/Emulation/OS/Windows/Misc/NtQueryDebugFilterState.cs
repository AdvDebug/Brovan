namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDebugFilterState : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NTSTATUS.STATUS_DEBUGGER_INACTIVE;
        }
    }
}
