using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtCancelIoFileEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoRequestToCancel = Instance.WinHelper.GetArg(1);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(2);

            NTSTATUS Status = NtCancelIoFile.ResolveFile(Instance, FileHandle, IoStatusBlockPtr, out WinFile File);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // Any thread of the process, and a NULL request matches every one on the file.
            int Cancelled = Instance.WinHelper.PipeRequests.Cancel(Instance, File, IoRequestToCancel, -1) +
                Instance.WinHelper.AfdRequests.Cancel(Instance, File, IoRequestToCancel, -1);
            Status = Cancelled != 0 ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NOT_FOUND;

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
            return Status;
        }
    }
}
