using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateTimer2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong TimerHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong TimerIdPtr = Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
                ulong Attributes = (uint)Instance.WinHelper.GetArg64(3);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(4);

                if (TimerHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(TimerHandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (TimerIdPtr != 0 && !Instance.IsRegionMapped(TimerIdPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (ObjectAttributesPtr != 0 && !Instance.IsRegionMapped(ObjectAttributesPtr, 0x30))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint TimerId = Instance.WinHelper.GenerateRandomPID();

                string Name = "Timer_" + TimerId.ToString();

                WinTimer Timer = new WinTimer
                {
                    Name = Name,
                    TimerId = TimerId,
                    Attributes = (uint)Attributes,
                    Signaled = false
                };

                WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Timer, (AccessMask)DesiredAccess);
                Instance.WinHelper.WinHandles.Add(Handle);

                if (!Instance._emulator.WriteMemory(TimerHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (TimerIdPtr != 0)
                {
                    if (!Instance._emulator.WriteMemory(TimerIdPtr, TimerId))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

                uint TimerHandlePtr = Instance.ReadMemoryUInt(SP + 4);
                uint TimerIdPtr = Instance.ReadMemoryUInt(SP + 8);
                uint ObjectAttributesPtr = Instance.ReadMemoryUInt(SP + 12);
                uint Attributes = Instance.ReadMemoryUInt(SP + 16);
                uint DesiredAccess = Instance.ReadMemoryUInt(SP + 20);

                if (TimerHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(TimerHandlePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (TimerIdPtr != 0 && !Instance.IsRegionMapped(TimerIdPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (ObjectAttributesPtr != 0 && !Instance.IsRegionMapped(ObjectAttributesPtr, 0x18))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint TimerId = Instance.WinHelper.GenerateRandomPID();

                string Name = "Timer_" + TimerId.ToString();

                WinTimer Timer = new WinTimer
                {
                    Name = Name,
                    TimerId = TimerId,
                    Attributes = Attributes,
                    Signaled = false
                };

                WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Timer, (AccessMask)DesiredAccess);
                Instance.WinHelper.WinHandles.Add(Handle);

                if (!Instance._emulator.WriteMemory(TimerHandlePtr, (uint)Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (TimerIdPtr != 0)
                {
                    if (!Instance._emulator.WriteMemory(TimerIdPtr, TimerId))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}