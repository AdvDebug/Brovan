using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAssociateWaitCompletionPacket : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong WaitCompletionPacketHandle = Instance.WinHelper.GetArg64(0);
                ulong IoCompletionHandle = Instance.WinHelper.GetArg64(1);
                ulong TargetObjectHandle = Instance.WinHelper.GetArg64(2);
                ulong KeyContext = Instance.WinHelper.GetArg64(3);
                ulong ApcContext = Instance.WinHelper.GetArg64(4);
                NTSTATUS IoStatus = (NTSTATUS)(uint)Instance.WinHelper.GetArg64(5);
                ulong IoStatusInformation = Instance.WinHelper.GetArg64(6);
                ulong AlreadySignaledPtr = Instance.WinHelper.GetArg64(7);

                if (!Instance.WinHelper.HandleExists(WaitCompletionPacketHandle, HandleType.WaitCompletionPacketHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (!Instance.WinHelper.HandleExists(IoCompletionHandle, HandleType.IoCompletionHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (!Instance.WinHelper.HandleExists(TargetObjectHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinWaitCompletionPacket Packet = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(WaitCompletionPacketHandle);
                if (Packet != null)
                {
                    Packet.IoCompletionHandle = IoCompletionHandle;
                    Packet.TargetObjectHandle = TargetObjectHandle;
                    Packet.KeyContext = KeyContext;
                    Packet.ApcContext = ApcContext;
                    Packet.IoStatus = IoStatus;
                    Packet.IoStatusInformation = IoStatusInformation;
                    Packet.Associated = true;
                    Packet.QueuedCompletion = false;
                    Instance.MaterializeSignaledWaitPackets(IoCompletionHandle);
                }

                if (AlreadySignaledPtr != 0)
                {
                    if (!Instance.IsRegionMapped(AlreadySignaledPtr, 1))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    byte AlreadySignaled = Packet != null && Packet.QueuedCompletion ? (byte)1 : (byte)0;
                    if (!Instance.WinHelper.WriteByte(AlreadySignaledPtr, AlreadySignaled))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }

            uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            uint WaitCompletionPacketHandle32 = Instance.ReadMemoryUInt(ESP + 4);
            uint IoCompletionHandle32 = Instance.ReadMemoryUInt(ESP + 8);
            uint TargetObjectHandle32 = Instance.ReadMemoryUInt(ESP + 12);
            uint KeyContext32 = Instance.ReadMemoryUInt(ESP + 16);
            uint ApcContext32 = Instance.ReadMemoryUInt(ESP + 20);
            NTSTATUS IoStatus32 = (NTSTATUS)Instance.ReadMemoryUInt(ESP + 24);
            uint IoStatusInformation32 = Instance.ReadMemoryUInt(ESP + 28);
            uint AlreadySignaledPtr32 = Instance.ReadMemoryUInt(ESP + 32);

            if (!Instance.WinHelper.HandleExists(WaitCompletionPacketHandle32, HandleType.WaitCompletionPacketHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Instance.WinHelper.HandleExists(IoCompletionHandle32, HandleType.IoCompletionHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Instance.WinHelper.HandleExists(TargetObjectHandle32))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinWaitCompletionPacket Packet32 = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(WaitCompletionPacketHandle32);
            if (Packet32 != null)
            {
                Packet32.IoCompletionHandle = IoCompletionHandle32;
                Packet32.TargetObjectHandle = TargetObjectHandle32;
                Packet32.KeyContext = KeyContext32;
                Packet32.ApcContext = ApcContext32;
                Packet32.IoStatus = IoStatus32;
                Packet32.IoStatusInformation = IoStatusInformation32;
                Packet32.Associated = true;
                Packet32.QueuedCompletion = false;
                Instance.MaterializeSignaledWaitPackets(IoCompletionHandle32);
            }

            if (AlreadySignaledPtr32 != 0)
            {
                if (!Instance.IsRegionMapped(AlreadySignaledPtr32, 1))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                byte AlreadySignaled32 = Packet32 != null && Packet32.QueuedCompletion ? (byte)1 : (byte)0;
                if (!Instance.WinHelper.WriteByte(AlreadySignaledPtr32, AlreadySignaled32))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}