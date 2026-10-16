namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAccessCheckByType : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            return NtAccessCheck.Check(Instance, DescriptorPtr: Helper.GetArg(0), SelfSidPtr: Helper.GetArg(1), TokenHandle: Helper.GetArg(2), Desired: (uint)Helper.GetArg(3),
                ObjectTypeListLength: (uint)Helper.GetArg(5), MappingPtr: Helper.GetArg(6), PrivilegeSetPtr: Helper.GetArg(7), PrivilegeSetLengthPtr: Helper.GetArg(8),
                GrantedAccessPtr: Helper.GetArg(9), AccessStatusPtr: Helper.GetArg(10));
        }
    }
}
