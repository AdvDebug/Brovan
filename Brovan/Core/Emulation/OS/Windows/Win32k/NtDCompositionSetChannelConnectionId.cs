using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionSetChannelConnectionId : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            uint Slot = Instance.WinHelper.GetArg32(1);
            ulong ConnectionId = Instance._binary.Architecture == BinaryArchitecture.x64
                ? Instance.WinHelper.GetArg(2)
                : Instance.WinHelper.GetWideArg(2);

            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            int Index = Slot != 0 ? 1 : 0;
            if (ConnectionId != 0 && Channel.ConnectionIds[Index] != 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Channel.ConnectionIds[Index] = ConnectionId;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
