using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtCancelIoFile : IWinSyscall
    {
        // Statuses follow IopReferenceFileObject. The I/O status block is probed before the handle.
        internal static NTSTATUS ResolveFile(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlockPtr, out WinFile File)
        {
            File = null;

            if (!Instance.IsMemoryRangeMapped(IoStatusBlockPtr, (ulong)Instance.WinHelper.PointerSize * 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            IHandleObject Object = Instance.WinHelper.HandleManager.GetObjectByHandle(FileHandle);
            if (Object == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            File = Object as WinFile;
            return File != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(1);

            NTSTATUS Status = ResolveFile(Instance, FileHandle, IoStatusBlockPtr, out WinFile File);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // Only the calling thread's requests, and the call returns once they ended.
            Instance.WinHelper.PipeRequests.Cancel(Instance, File, 0, Instance.CurrentThreadId);
            Instance.WinHelper.AfdRequests.Cancel(Instance, File, 0, Instance.CurrentThreadId);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
