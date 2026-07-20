using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCancelWaitCompletionPacket : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong WaitCompletionPacketHandle = Instance.WinHelper.GetArg(0);
                ulong RemoveSignaledPacket = Instance.WinHelper.GetArg(1);

                if (!Instance.WinHelper.HandleExists(WaitCompletionPacketHandle, HandleType.WaitCompletionPacketHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinWaitCompletionPacket Packet = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(WaitCompletionPacketHandle);
                if (Packet != null)
                {
                    Packet.Associated = false;
                    Packet.QueuedCompletion = false;
                }
                _ = RemoveSignaledPacket;
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint WaitCompletionPacketHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint RemoveSignaledPacket32 = (uint)Instance.WinHelper.GetArg(1);

            if (!Instance.WinHelper.HandleExists(WaitCompletionPacketHandle32, HandleType.WaitCompletionPacketHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinWaitCompletionPacket Packet32 = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(WaitCompletionPacketHandle32);
            if (Packet32 != null)
            {
                Packet32.Associated = false;
                Packet32.QueuedCompletion = false;
            }
            _ = RemoveSignaledPacket32;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
