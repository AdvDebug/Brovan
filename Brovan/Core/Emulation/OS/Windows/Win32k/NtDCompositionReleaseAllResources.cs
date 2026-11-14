namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionReleaseAllResources : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            ulong DeletedPtr = Instance.WinHelper.GetArg(1);

            if (DeletedPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Channel.ReleaseAllResources(Instance);

            // No handled record sets a deletion tag, so the byte is 0.
            return Instance.WinHelper.WriteByte(DeletedPtr, 0) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
