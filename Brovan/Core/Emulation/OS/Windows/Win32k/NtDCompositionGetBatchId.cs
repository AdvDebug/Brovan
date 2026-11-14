namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionGetBatchId : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            uint Selector = Instance.WinHelper.GetArg32(1);
            ulong ValuePtr = Instance.WinHelper.GetArg(2);

            if (ValuePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT answers a selector it does not know with 0.
            uint Value = Selector switch
            {
                0 => Channel.Committed,
                1 => Channel.Processed,
                2 => Channel.Confirmed,
                _ => 0,
            };

            return Instance.WinHelper.WriteUInt32(ValuePtr, Value) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
