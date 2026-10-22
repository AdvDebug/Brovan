namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICloseAdapter : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Win32kDxgk.TryReadHandleArgument(Instance, out uint Handle) && Instance.WinHelper.DxgkProcess.TryRemove<DxgkAdapter>(Handle)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
