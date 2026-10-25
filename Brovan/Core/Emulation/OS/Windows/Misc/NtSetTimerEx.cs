using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimerEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong TimerHandle = Helper.GetArg(0);
            uint TimerSetInformationClass = (uint)Helper.GetArg(1);
            ulong TimerSetInformation = Helper.GetArg(2);
            uint TimerSetInformationLength = (uint)Helper.GetArg(3);

            int PointerSize = Helper.PointerSize;
            ulong ApcRoutineOffset = 8;
            ulong PeriodOffset = ApcRoutineOffset + 3 * (ulong)PointerSize;
            ulong PreviousStateOffset = PeriodOffset + 8;
            uint InfoSize = (uint)(PreviousStateOffset + (ulong)PointerSize + 7) & ~7u;

            // The WOW64 thunk copies the input to an aligned buffer, so only a native caller can misalign it.
            if (PointerSize == 8 && TimerSetInformationLength != 0 && (TimerSetInformation & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (TimerSetInformationClass != (uint)TIMER_SET_INFORMATION_CLASS.TimerSetCoalescableTimer)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            // NT takes exactly the native size, and the WOW64 thunk any length from the 32-bit size up.
            if (PointerSize == 8 ? TimerSetInformationLength != InfoSize : TimerSetInformationLength < InfoSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(TimerSetInformation, InfoSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(TimerSetInformation));
            Helper.TryReadPointer(TimerSetInformation + ApcRoutineOffset, out ulong ApcRoutine);
            Helper.TryReadPointer(TimerSetInformation + ApcRoutineOffset + (ulong)PointerSize, out ulong ApcContext);
            Helper.TryReadPointer(TimerSetInformation + ApcRoutineOffset + 2 * (ulong)PointerSize, out ulong WakeContext);
            uint Period = Instance._emulator.ReadMemoryUInt(TimerSetInformation + PeriodOffset);
            uint TolerableDelay = Instance._emulator.ReadMemoryUInt(TimerSetInformation + PeriodOffset + 4);
            Helper.TryReadPointer(TimerSetInformation + PreviousStateOffset, out ulong PreviousStatePtr);

            if (Period > int.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            WinTimer Timer = Helper.GetTimerByHandle(TimerHandle, AccessMask.TimerModifyState);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Timer is WinIRTimer IRTimer)
            {
                if (ApcRoutine != 0 || ApcContext != 0 || WakeContext != 0 || TolerableDelay != 0 || PreviousStatePtr != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                return NtTimerHelpers.SetTimer2(Instance, IRTimer, TimerHandle, DueTime, Period * NtTimerHelpers.IntervalsPerMillisecond, ReadOnlySpan<byte>.Empty);
            }

            Instance.CanSatisfyWaitHandle(TimerHandle);
            long DueMilliseconds = Helper.TimeoutToMilliseconds(DueTime);
            NtTimerHelpers.SetTimerApc(Instance, Timer, ApcRoutine, ApcContext);
            NtTimerHelpers.ArmTimer(Instance, Timer, TimerHandle, DueMilliseconds, Period, out bool WasSignaled);
            return NtTimerHelpers.WritePreviousState(Instance, PreviousStatePtr, WasSignaled);
        }
    }
}
