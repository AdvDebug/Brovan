using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimerEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong TimerHandle = Instance.WinHelper.GetArg(0);
                ulong TimerSetInformationClass = Instance.WinHelper.GetArg(1);
                ulong TimerSetInformation = Instance.WinHelper.GetArg(2);
                ulong TimerSetInformationLength = Instance.WinHelper.GetArg(3);

                return HandleSetTimerEx64(Instance, TimerHandle, TimerSetInformationClass, TimerSetInformation, TimerSetInformationLength);
            }


            uint TimerHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint TimerSetInformationClass32 = (uint)Instance.WinHelper.GetArg(1);
            uint TimerSetInformation32 = (uint)Instance.WinHelper.GetArg(2);
            uint TimerSetInformationLength32 = (uint)Instance.WinHelper.GetArg(3);

            return HandleSetTimerEx32(Instance, TimerHandle32, TimerSetInformationClass32, TimerSetInformation32, TimerSetInformationLength32);
        }

        private static NTSTATUS HandleSetTimerEx64(BinaryEmulator Instance, ulong TimerHandle, ulong TimerSetInformationClass, ulong TimerSetInformation, ulong TimerSetInformationLength)
        {
            if (TimerSetInformationClass != (ulong)TIMER_SET_INFORMATION_CLASS.TimerSetCoalescableTimer)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (TimerSetInformation == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (TimerSetInformationLength < 0x30)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(TimerSetInformation, 0x30))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinTimer Timer = Instance.WinHelper.GetTimerByHandle(TimerHandle, AccessMask.TimerModifyState);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Instance.CanSatisfyWaitHandle(TimerHandle);
            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(TimerSetInformation + 0x00));
            uint PeriodRaw = Instance._emulator.ReadMemoryUInt(TimerSetInformation + 0x20);
            ulong PreviousStatePtr = Instance._emulator.ReadMemoryULong(TimerSetInformation + 0x28);

            long DueMilliseconds = NtTimerHelpers.ConvertDueTimeToMilliseconds(Instance, DueTime);
            long PeriodMilliseconds = PeriodRaw == 0 ? 0 : PeriodRaw;

            NtTimerHelpers.ArmTimer(Instance, Timer, TimerHandle, DueMilliseconds, PeriodMilliseconds, out bool WasSignaled);
            return NtTimerHelpers.WritePreviousState(Instance, PreviousStatePtr, WasSignaled);
        }

        private static NTSTATUS HandleSetTimerEx32(BinaryEmulator Instance, uint TimerHandle, uint TimerSetInformationClass, uint TimerSetInformation, uint TimerSetInformationLength)
        {
            if (TimerSetInformationClass != (uint)TIMER_SET_INFORMATION_CLASS.TimerSetCoalescableTimer)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (TimerSetInformation == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (TimerSetInformationLength < 0x20)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(TimerSetInformation, 0x20))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinTimer Timer = Instance.WinHelper.GetTimerByHandle(TimerHandle, AccessMask.TimerModifyState);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Instance.CanSatisfyWaitHandle(TimerHandle);
            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(TimerSetInformation + 0x00));
            uint PeriodRaw = Instance._emulator.ReadMemoryUInt(TimerSetInformation + 0x14);
            uint PreviousStatePtr = Instance._emulator.ReadMemoryUInt(TimerSetInformation + 0x1C);

            long DueMilliseconds = NtTimerHelpers.ConvertDueTimeToMilliseconds(Instance, DueTime);
            long PeriodMilliseconds = PeriodRaw == 0 ? 0 : PeriodRaw;

            NtTimerHelpers.ArmTimer(Instance, Timer, TimerHandle, DueMilliseconds, PeriodMilliseconds, out bool WasSignaled);
            return NtTimerHelpers.WritePreviousState(Instance, PreviousStatePtr, WasSignaled);
        }
    }
}
