using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDestroyCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Cursor = Instance.WinHelper.GetArg(0);
            bool Destroyed = Win32kHelper.DestroyCursorIcon(Instance, Cursor);

            Instance.SetLastWinError(Destroyed ? 0u : Win32kHelper.ERROR_INVALID_HANDLE);
            Instance.SetBooleanSyscallReturn(Destroyed);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
