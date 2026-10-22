namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIDestroyContext : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryGetHandleArgument(Instance, out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance.WinHelper.DxgkProcess.Destroy(Instance, Context);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
