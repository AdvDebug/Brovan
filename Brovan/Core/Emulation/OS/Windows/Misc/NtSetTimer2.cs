using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimer2 : IWinSyscall
    {
        private static long ConvertDueTimeToMilliseconds(BinaryEmulator Instance, long Value)
        {
            if (Value < 0)
                return ConvertIntervalToMilliseconds(-Value);

            long Now = Instance.GetEmulatedSystemTimeFileTimeUtc();
            if (Value <= Now)
                return 0;

            return ConvertIntervalToMilliseconds(Value - Now);
        }

        private static long ConvertIntervalToMilliseconds(long Value)
        {
            if (Value <= 0)
                return 0;

            return (Value + 9999) / 10000;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong TimerHandle = Instance.WinHelper.GetArg(0);
            ulong DueTimePtr = Instance.WinHelper.GetArg(1);
            ulong PeriodPtr = Instance.WinHelper.GetArg(2);
            ulong ParametersPtr = Instance.WinHelper.GetArg(3);

            if (DueTimePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DueTimePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (PeriodPtr != 0 && !Instance.IsRegionMapped(PeriodPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ParametersPtr != 0 && !Instance.IsRegionMapped(ParametersPtr, 0x10))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinTimer Timer = Instance.WinHelper.HandleManager.GetObjectByHandle<WinTimer>(TimerHandle);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(DueTimePtr));
            long Period = PeriodPtr != 0 ? unchecked((long)Instance._emulator.ReadMemoryULong(PeriodPtr)) : 0;

            long DueMilliseconds = ConvertDueTimeToMilliseconds(Instance, DueTime);
            long PeriodMilliseconds = Period == 0 ? 0 : ConvertIntervalToMilliseconds(Period < 0 ? -Period : Period);

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

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
