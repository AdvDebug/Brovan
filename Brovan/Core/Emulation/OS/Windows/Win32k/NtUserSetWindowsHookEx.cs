using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowsHookEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int HookId = (int)Instance.WinHelper.GetArg(3);
            ulong HookProc = Instance.WinHelper.GetArg(4);

            if (HookProc == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(Instance.WinHelper.RegisterWindowsHook(HookId, HookProc));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
