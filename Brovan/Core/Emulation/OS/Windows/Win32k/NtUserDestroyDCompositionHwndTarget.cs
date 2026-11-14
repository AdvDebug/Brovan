namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDestroyDCompositionHwndTarget : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Slot = Instance.WinHelper.GetArg32(1);

            NTSTATUS Status = Slot < Compositor.TargetSlots
                ? Instance.WinHelper.Composition.DestroyTarget(Instance, Hwnd, Slot)
                : NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Status != NTSTATUS.STATUS_SUCCESS)
                Win32kHelper.SetLastStatus(Instance, Status, SetError: true);

            Instance.SetBooleanSyscallReturn(Status == NTSTATUS.STATUS_SUCCESS);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
