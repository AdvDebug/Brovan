using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateWaitCompletionPacket : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong WaitCompletionPacketHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong ObjectAttributes = Instance.WinHelper.GetArg(2);

                if (WaitCompletionPacketHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(WaitCompletionPacketHandlePtr, (uint)Instance.WinHelper.PointerSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                _ = ObjectAttributes;

                uint Id = Instance.WinHelper.GenerateRandomPID();
                WinWaitCompletionPacket Packet = new WinWaitCompletionPacket
                {
                    Name = "WaitCompletionPacket_" + Id.ToString()
                };

                WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Packet, (AccessMask)DesiredAccess);
                Instance.WinHelper.AddWinHandle(Handle);

                if (!Instance.WinHelper.WritePointer(WaitCompletionPacketHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            uint WaitCompletionPacketHandlePtr32 = (uint)Instance.WinHelper.GetArg(0);
            uint DesiredAccess32 = (uint)Instance.WinHelper.GetArg(1);
            uint ObjectAttributes32 = (uint)Instance.WinHelper.GetArg(2);

            if (WaitCompletionPacketHandlePtr32 == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(WaitCompletionPacketHandlePtr32, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            _ = ObjectAttributes32;

            uint Id32 = Instance.WinHelper.GenerateRandomPID();
            WinWaitCompletionPacket Packet32 = new WinWaitCompletionPacket
            {
                Name = "WaitCompletionPacket_" + Id32.ToString()
            };

            WinHandle Handle32 = Instance.WinHelper.HandleManager.AddHandle(Packet32, (AccessMask)DesiredAccess32);
            Instance.WinHelper.AddWinHandle(Handle32);

            if (!Instance._emulator.WriteMemory(WaitCompletionPacketHandlePtr32, (uint)Handle32.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
