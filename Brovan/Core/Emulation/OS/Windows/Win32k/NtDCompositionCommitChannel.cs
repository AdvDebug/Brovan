namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionCommitChannel : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            ulong BatchIdPtr = Instance.WinHelper.GetArg(1);
            ulong DeletedPtr = Instance.WinHelper.GetArg(2);
            uint Flags = Instance.WinHelper.GetArg32(3);
            ulong ProtocolBlocks = Instance.WinHelper.GetArg(5);
            ulong Handles = Instance.WinHelper.GetArg(6);
            uint HandleCount = Instance.WinHelper.GetArg32(7);

            // NT: protocol blocks and a handle array come only from DWM, which no guest process is.
            if (DeletedPtr == 0 || ProtocolBlocks != 0 || Handles != 0 || HandleCount != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT ignores a synchronization handle it cannot resolve, and Brovan makes no synchronization objects.
            // Flag 2 only marks the last commit of a frame.
            Status = Channel.Commit(Instance, (Flags & 1) != 0, out uint BatchId);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // No handled record sets a deletion tag, so the byte is 0.
            if ((BatchIdPtr == 0 || Instance.WinHelper.WriteUInt32(BatchIdPtr, BatchId)) && Instance.WinHelper.WriteByte(DeletedPtr, 0))
                return NTSTATUS.STATUS_SUCCESS;

            return NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
