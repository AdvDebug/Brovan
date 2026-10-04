using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong TimerHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong TimerType = (uint)Instance.WinHelper.GetArg(3);

            return HandleCreateTimer(Instance, TimerHandlePtr, DesiredAccess, ObjectAttributesPtr, TimerType);
        }

        private static NTSTATUS HandleCreateTimer(BinaryEmulator Instance, ulong TimerHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, ulong TimerType)
        {
            if (TimerHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(TimerHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TimerType > (ulong)TIMER_TYPE.SynchronizationTimer)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinTimer? Existing, out Status))
                return Status;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Existing != null
                ? Instance.WinHelper.OpenObjectHandle(Existing, Permissions)
                : Instance.WinHelper.CreateTimerHandle(Name, (TIMER_TYPE)TimerType, Permissions);

            if (!Instance.WinHelper.WritePointer(TimerHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
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
            Instance.InvalidateWindowsTimerDue();

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
