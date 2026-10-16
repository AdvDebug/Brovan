namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcImpersonateClientOfPort : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return AlpcMessaging.ImpersonateClient(Instance, Helper.GetArg(0), Helper.GetArg(1), Helper.GetArg(2));
        }
    }
}
