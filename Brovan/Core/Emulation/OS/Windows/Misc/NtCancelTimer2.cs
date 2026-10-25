using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCancelTimer2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong TimerHandle = Instance.WinHelper.GetArg(0);
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(TimerHandle, AccessMask.TimerModifyState, out WinIRTimer Timer);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return NtTimerHelpers.SetTimer2(Instance, Timer, TimerHandle, null, 0, ReadOnlySpan<byte>.Empty);
        }
    }
}
