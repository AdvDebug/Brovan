using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong TimerHandle = Instance.WinHelper.GetArg(0);
            ulong DueTimePtr = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            bool ResumeTimer = (byte)Instance.WinHelper.GetArg(4) != 0;
            int Period = unchecked((int)Instance.WinHelper.GetArg(5));
            ulong PreviousStatePtr = Instance.WinHelper.GetArg(6);

            if (!Instance.IsRegionMapped(DueTimePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Period < 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_6;

            WinTimer Timer = Instance.WinHelper.GetTimerByHandle(TimerHandle, AccessMask.TimerModifyState);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(DueTimePtr));
            if (Timer is WinIRTimer IRTimer)
            {
                if (ApcRoutine != 0 || ApcContext != 0 || ResumeTimer || PreviousStatePtr != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                return NtTimerHelpers.SetTimer2(Instance, IRTimer, TimerHandle, DueTime, Period * NtTimerHelpers.IntervalsPerMillisecond, ReadOnlySpan<byte>.Empty);
            }

            Instance.CanSatisfyWaitHandle(TimerHandle);
            long DueMilliseconds = Instance.WinHelper.TimeoutToMilliseconds(DueTime);
            NtTimerHelpers.SetTimerApc(Instance, Timer, ApcRoutine, ApcContext);
            NtTimerHelpers.ArmTimer(Instance, Timer, TimerHandle, DueMilliseconds, Period, out bool WasSignaled);
            return NtTimerHelpers.WritePreviousState(Instance, PreviousStatePtr, WasSignaled);
        }
    }
}
