namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionSetChannelCommitCompletionEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
            bool Serialized = Instance.WinHelper.GetArg32(2) != 0;

            if (EventHandle == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Channel.HasCompletionEvent)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Status = Instance.WinHelper.ReferenceObjectByHandle(EventHandle, AccessMask.EventModifyState, out WinEvent Event);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Channel.SetCompletionEvent(Event, Serialized);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
