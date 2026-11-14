namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionSynchronize : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            ulong IdPtr = Instance.WinHelper.GetArg(1);

            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = Channel.Synchronize(out ulong SynchronizationId);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT checks the output only after the fragment took its ID, so a null output still uses the fragment up.
            if (IdPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance.WinHelper.WriteUInt64(IdPtr, SynchronizationId) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
