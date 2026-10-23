namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtCreateCompositionSurfaceHandle : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong AttributesPtr = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong HandlePtr = Instance.WinHelper.GetArg(2);

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(AttributesPtr, out string Name, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Name != null)
                return Instance.WinUnimplemented;

            if (HandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance.WinHelper.DxgkProcess.InsertNtObject(Instance, new DxgkCompositionSurface(), DesiredAccess, HandlePtr);
        }
    }
}
