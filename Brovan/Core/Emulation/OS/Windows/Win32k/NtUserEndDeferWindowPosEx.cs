using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEndDeferWindowPosEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DeferHandle = Instance.WinHelper.GetArg(0);
            bool Applied = Win32kHelper.EndDeferWindowPos(Instance, DeferHandle, out bool Pending);

            Instance.SetLastWinError(Applied ? 0u : Win32kHelper.ERROR_INVALID_HANDLE);
            if (Pending)
                return NTSTATUS.STATUS_SUCCESS;

            Win32kHelper.ReturnAfterNotifications(Instance, Applied ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
