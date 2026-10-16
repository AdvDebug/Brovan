namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenThreadTokenEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return NtOpenThreadToken.Open(Instance, ThreadHandle: Helper.GetArg(0), DesiredAccess: (uint)Helper.GetArg(1), OpenAsSelf: (byte)Helper.GetArg(2) != 0, HandleAttributes: (uint)Helper.GetArg(3), TokenHandlePtr: Helper.GetArg(4));
        }
    }
}
