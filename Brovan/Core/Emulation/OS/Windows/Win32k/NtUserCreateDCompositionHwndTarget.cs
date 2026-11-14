namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserCreateDCompositionHwndTarget : IWinSyscall
    {
        // NT reports a failure through the last status only, which dcomp reads with RtlGetLastNtStatus.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Slot = Instance.WinHelper.GetArg32(1);
            ulong HandlePtr = Instance.WinHelper.GetArg(2);

            NTSTATUS Status = HandlePtr != 0 && Slot < Compositor.TargetSlots
                ? Instance.WinHelper.Composition.TryCreateTarget(Instance, Hwnd, Slot, HandlePtr)
                : NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Status != NTSTATUS.STATUS_SUCCESS)
                Win32kHelper.SetLastStatus(Instance, Status, SetError: false);

            Instance.SetBooleanSyscallReturn(Status == NTSTATUS.STATUS_SUCCESS);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
