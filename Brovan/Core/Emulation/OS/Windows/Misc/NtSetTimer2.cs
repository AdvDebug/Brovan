using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimer2 : IWinSyscall
    {
        private const int SetParametersSize = 16;

        // NT reads all three inputs before it references the timer.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong TimerHandle = Helper.GetArg(0);
            ulong DueTimePtr = Helper.GetArg(1);
            ulong PeriodPtr = Helper.GetArg(2);
            ulong ParametersPtr = Helper.GetArg(3);

            if (DueTimePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            ulong Period = 0;
            Span<byte> Parameters = stackalloc byte[SetParametersSize];
            if (!Helper.TryReadUInt64(DueTimePtr, out ulong DueTime) || (PeriodPtr != 0 && !Helper.TryReadUInt64(PeriodPtr, out Period))
                || (ParametersPtr != 0 && !Instance.ReadMemory(ParametersPtr, Parameters)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Helper.ReferenceObjectByHandle(TimerHandle, AccessMask.TimerModifyState, out WinIRTimer Timer);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return NtTimerHelpers.SetTimer2(Instance, Timer, TimerHandle, unchecked((long)DueTime), unchecked((long)Period),
                ParametersPtr != 0 ? Parameters : ReadOnlySpan<byte>.Empty);
        }
    }
}
