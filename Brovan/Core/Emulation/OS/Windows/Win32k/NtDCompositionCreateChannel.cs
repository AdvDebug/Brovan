namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionCreateChannel : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ChannelPtr = Instance.WinHelper.GetArg(0);
            ulong SizePtr = Instance.WinHelper.GetArg(1);
            ulong MappingPtr = Instance.WinHelper.GetArg(2);

            if (ChannelPtr == 0 || SizePtr == 0 || MappingPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.TryReadUInt32(SizePtr, out uint RequestedSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            CompositionProcess Composition = Instance.WinHelper.Composition;
            NTSTATUS Status = Composition.TryCreateChannel(Instance, RequestedSize, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Instance.WinHelper.WriteUInt32(SizePtr, Channel.Size)
                && Instance.WinHelper.WriteUInt32(ChannelPtr, Channel.Id)
                && Instance.WinHelper.WritePointer(MappingPtr, Channel.Base))
                return NTSTATUS.STATUS_SUCCESS;

            Composition.DestroyChannel(Instance, Channel.Id);
            return NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
