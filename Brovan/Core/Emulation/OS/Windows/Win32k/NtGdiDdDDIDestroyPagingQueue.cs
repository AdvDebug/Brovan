namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIDestroyPagingQueue : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryGetHandleArgument(Instance, out DxgkPagingQueue Queue))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance.WinHelper.DxgkProcess.Destroy(Instance, Queue);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
