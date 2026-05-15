namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetWnfProcessNotificationEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
