using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong TimerHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
                ulong TimerType = (uint)Instance.WinHelper.GetArg(3);

                return HandleCreateTimer64(Instance, TimerHandlePtr, DesiredAccess, ObjectAttributesPtr, TimerType);
            }


            uint TimerHandlePtr32 = (uint)Instance.WinHelper.GetArg(0);
            uint DesiredAccess32 = (uint)Instance.WinHelper.GetArg(1);
            uint ObjectAttributesPtr32 = (uint)Instance.WinHelper.GetArg(2);
            uint TimerType32 = (uint)Instance.WinHelper.GetArg(3);

            return HandleCreateTimer32(Instance, TimerHandlePtr32, DesiredAccess32, ObjectAttributesPtr32, TimerType32);
        }

        private static NTSTATUS HandleCreateTimer64(BinaryEmulator Instance, ulong TimerHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, ulong TimerType)
        {
            if (TimerHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(TimerHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TimerType > (ulong)TIMER_TYPE.SynchronizationTimer)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!NtTimerHelpers.TryReadTimerObjectName64(Instance, ObjectAttributesPtr, out string Name, out NTSTATUS NameStatus))
                return NameStatus;

            WinHandle Handle = Instance.WinHelper.CreateTimerHandle(Name, (TIMER_TYPE)TimerType, (AccessMask)(uint)DesiredAccess);
            if (!Instance.WinHelper.WritePointer(TimerHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleCreateTimer32(BinaryEmulator Instance, uint TimerHandlePtr, uint DesiredAccess, uint ObjectAttributesPtr, uint TimerType)
        {
            if (TimerHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(TimerHandlePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TimerType > (uint)TIMER_TYPE.SynchronizationTimer)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!NtTimerHelpers.TryReadTimerObjectName32(Instance, ObjectAttributesPtr, out string Name, out NTSTATUS NameStatus))
                return NameStatus;

            WinHandle Handle = Instance.WinHelper.CreateTimerHandle(Name, (TIMER_TYPE)TimerType, (AccessMask)DesiredAccess);
            if (!Instance._emulator.WriteMemory(TimerHandlePtr, (uint)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal static class NtTimerHelpers
    {
        public static long ConvertDueTimeToMilliseconds(BinaryEmulator Instance, long Value)
        {
            if (Value < 0)
                return ConvertIntervalToMilliseconds(-Value);

            long Now = Instance.GetEmulatedSystemTimeFileTimeUtc();
            if (Value <= Now)
                return 0;

            return ConvertIntervalToMilliseconds(Value - Now);
        }

        public static long ConvertIntervalToMilliseconds(long Value)
        {
            if (Value <= 0)
                return 0;

            return (Value + 9999) / 10000;
        }

        public static void ArmTimer(BinaryEmulator Instance, WinTimer Timer, ulong TimerHandle, long DueMilliseconds, long PeriodMilliseconds, out bool WasSignaled)
        {
            WasSignaled = Timer.Signaled;
            Timer.Signaled = false;
            Timer.Active = true;
            Timer.DueTick = Instance.CreateEmulatedDeadlineMilliseconds(DueMilliseconds);
            Timer.PeriodMilliseconds = PeriodMilliseconds;

            if (DueMilliseconds == 0)
            {
                Timer.Signaled = true;
                if (Timer.PeriodMilliseconds == 0)
                    Timer.Active = false;
                else
                    Timer.DueTick = Instance.CreateEmulatedDeadlineMilliseconds(Timer.PeriodMilliseconds);

                if (Instance.WakeWorkerFactoryWaitersForObject(TimerHandle) || Instance.HasHandleWaiters(TimerHandle))
                    Instance._emulator.StopEmulation();
            }
        }

        public static bool TryReadTimerObjectName64(BinaryEmulator Instance, ulong ObjectAttributesPtr, out string Name, out NTSTATUS Status)
        {
            Name = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
                return true;

            const uint ObjectAttributesSize = 0x30;
            if (!Instance.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            ulong RootDirectory = Instance._emulator.ReadMemoryULong(ObjectAttributesPtr + 0x08);
            ulong ObjectName = Instance._emulator.ReadMemoryULong(ObjectAttributesPtr + 0x10);
            if (ObjectName == 0)
                return true;

            if (!Instance.WinHelper.TryReadUnicodeString(ObjectName, out string LocalName, out Status))
                return false;

            Name = Instance.WinHelper.ResolveObjectNameWithRootDirectory(RootDirectory, LocalName);
            if (string.IsNullOrEmpty(Name))
                Name = LocalName;

            return true;
        }

        public static bool TryReadTimerObjectName32(BinaryEmulator Instance, uint ObjectAttributesPtr, out string Name, out NTSTATUS Status)
        {
            Name = string.Empty;
            Status = NTSTATUS.STATUS_SUCCESS;

            if (ObjectAttributesPtr == 0)
                return true;

            const uint ObjectAttributesSize = 0x18;
            if (!Instance.IsRegionMapped(ObjectAttributesPtr, ObjectAttributesSize))
            {
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return false;
            }

            uint RootDirectory = Instance._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x04);
            uint ObjectName = Instance._emulator.ReadMemoryUInt(ObjectAttributesPtr + 0x08);
            if (ObjectName == 0)
                return true;

            if (!Instance.WinHelper.TryReadUnicodeString32(ObjectName, out string LocalName, out Status))
                return false;

            Name = Instance.WinHelper.ResolveObjectNameWithRootDirectory(RootDirectory, LocalName);
            if (string.IsNullOrEmpty(Name))
                Name = LocalName;

            return true;
        }

        public static NTSTATUS WritePreviousState(BinaryEmulator Instance, ulong PreviousStatePtr, bool WasSignaled)
        {
            if (PreviousStatePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (!Instance.IsRegionMapped(PreviousStatePtr, 1))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(PreviousStatePtr, (byte)(WasSignaled ? 1 : 0)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
