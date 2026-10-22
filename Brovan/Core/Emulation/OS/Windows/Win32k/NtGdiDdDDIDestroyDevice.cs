namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIDestroyDevice : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryGetHandleArgument(Instance, out DxgkDevice Device))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance.WinHelper.DxgkProcess.Destroy(Instance, Device);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
