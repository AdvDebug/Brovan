namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcDisconnectPort : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return AlpcMessaging.DisconnectPort(Instance, Helper.GetArg(0), (uint)Helper.GetArg(1));
        }
    }
}
