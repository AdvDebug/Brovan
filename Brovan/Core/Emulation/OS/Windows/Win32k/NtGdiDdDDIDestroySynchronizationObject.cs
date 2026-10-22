namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIDestroySynchronizationObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryGetHandleArgument(Instance, out DxgkFence Fence))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT: a paging queue's fence goes with its queue.
            if (Fence.OwnedByPagingQueue)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Instance.WinHelper.DxgkProcess.Destroy(Instance, Fence);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
