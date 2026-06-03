using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributes = Instance.WinHelper.GetArg64(2);
                uint EventType = (uint)Instance.WinHelper.GetArg64(3);
                bool InitialState = (byte)Instance.WinHelper.GetArg64(4, true) != 0;

                if (EventHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(EventHandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (EventType > 1)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
                WinHandle Handle = Instance.WinHelper.CreateEventHandle(null, EventType, InitialState, Permissions);
                if (!Instance._emulator.WriteMemory(EventHandlePtr, (ulong)Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }
            return Instance.WinUnimplemented;
        }
    }
}
