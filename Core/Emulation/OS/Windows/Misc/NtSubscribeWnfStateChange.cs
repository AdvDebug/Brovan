namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSubscribeWnfStateChange : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
