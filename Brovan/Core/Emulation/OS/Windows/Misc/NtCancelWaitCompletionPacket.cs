using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCancelWaitCompletionPacket : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong WaitCompletionPacketHandle = Instance.WinHelper.GetArg(0);
            bool RemoveSignaledPacket = (byte)Instance.WinHelper.GetArg(1) != 0;

            WinWaitCompletionPacket Packet = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(WaitCompletionPacketHandle);
            if (Packet == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Packet.Associated)
                return NTSTATUS.STATUS_CANCELLED;

            WinIoCompletion Completion = Instance.WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(Packet.IoCompletionHandle);
            if (Completion != null)
                Instance.MaterializeSignaledWaitPackets(Packet.IoCompletionHandle, Completion);

            if (Packet.QueuedCompletion)
            {
                if (!RemoveSignaledPacket)
                    return NTSTATUS.STATUS_PENDING;

                Completion?.Remove(Packet.QueuedEntry);
            }

            Packet.Disassociate();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
