using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAssociateWaitCompletionPacket : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong WaitCompletionPacketHandle = Instance.WinHelper.GetArg(0);
            ulong IoCompletionHandle = Instance.WinHelper.GetArg(1);
            ulong TargetObjectHandle = Instance.WinHelper.GetArg(2);
            ulong KeyContext = Instance.WinHelper.GetArg(3);
            ulong ApcContext = Instance.WinHelper.GetArg(4);
            NTSTATUS IoStatus = (NTSTATUS)(uint)Instance.WinHelper.GetArg(5);
            ulong IoStatusInformation = Instance.WinHelper.GetArg(6);
            ulong AlreadySignaledPtr = Instance.WinHelper.GetArg(7);

            WinWaitCompletionPacket Packet = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(WaitCompletionPacketHandle);
            WinIoCompletion Completion = Instance.WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(IoCompletionHandle);
            IHandleObject Target = Instance.WinHelper.HandleManager.GetObjectByHandle(TargetObjectHandle);
            if (Packet == null || Completion == null || Target == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            // NT: the target's wait object may not be a mutant or a queue, and a worker factory has none.
            WaitEntry TargetWait = Instance.ResolveWaitEntry(Target);
            if (TargetWait.Waitable is WinMutex or WinIoCompletion or WinWorkerFactory)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            // NT keeps a packet associated until its completion leaves the port.
            if (Packet.Associated)
                return NTSTATUS.STATUS_INVALID_PARAMETER_1;

            Packet.Completion = Completion;
            Packet.Target = TargetWait;
            Packet.KeyContext = KeyContext;
            Packet.ApcContext = ApcContext;
            Packet.IoStatus = IoStatus;
            Packet.IoStatusInformation = IoStatusInformation;
            Packet.Associated = true;
            if (Instance.WinHelper.HasPendingConnectReplies && Target is WinPort Port)
                AlpcMessaging.DeliverConnectReplyForRoute(Instance, Port, Completion);
            Instance.MaterializeSignaledWaitPackets(Completion);

            if (AlreadySignaledPtr != 0 && !Instance.WinHelper.WriteByte(AlreadySignaledPtr, Packet.QueuedCompletion ? (byte)1 : (byte)0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
