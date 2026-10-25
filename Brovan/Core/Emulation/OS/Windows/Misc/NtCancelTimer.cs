using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCancelTimer : IWinSyscall
    {
        // NT checks TIMER_MODIFY_STATE before the object type.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong TimerHandle = Helper.GetArg(0);
            ulong CurrentStatePtr = Helper.GetArg(1);

            if (CurrentStatePtr != 0 && Helper.ProbeForWrite(CurrentStatePtr, 1) != NTSTATUS.STATUS_SUCCESS)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Helper.ReferenceObjectByHandle(TimerHandle, AccessMask.TimerModifyState, out IHandleObject Object);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Object is WinIRTimer IRTimer)
            {
                return CurrentStatePtr != 0
                    ? NTSTATUS.STATUS_INVALID_PARAMETER
                    : NtTimerHelpers.SetTimer2(Instance, IRTimer, TimerHandle, null, 0, ReadOnlySpan<byte>.Empty);
            }

            if (Object is not WinTimer Timer)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            NtTimerHelpers.CancelTimer(Instance, Timer);
            if (CurrentStatePtr != 0 && !Helper.WriteByte(CurrentStatePtr, Timer.Signaled ? (byte)1 : (byte)0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
