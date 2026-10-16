namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcDeleteSecurityContext : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return AlpcMessaging.DeleteSecurityContext(Instance, Helper.GetArg(0), (uint)Helper.GetArg(1), Helper.GetArg(2));
        }
    }
}
