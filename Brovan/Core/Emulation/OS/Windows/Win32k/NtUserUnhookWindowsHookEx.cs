using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserUnhookWindowsHookEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hook = Instance.WinHelper.GetArg(0);

            Instance.SetRawSyscallReturn(Instance.WinHelper.UnregisterWindowsHook(Hook) ? 1u : 0u);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
