namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcCreateSecurityContext : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return AlpcMessaging.CreateSecurityContext(Instance, Helper.GetArg(0), (uint)Helper.GetArg(1), Helper.GetArg(2));
        }
    }
}
