using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserPostThreadMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.WinHelper.GetArg(0);
            uint Message = (uint)Instance.WinHelper.GetArg(1);
            ulong WParam = Instance.WinHelper.GetArg(2);
            ulong LParam = Instance.WinHelper.GetArg(3);

            if ((Message & 0xFFFE0000u) != 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // One message queue per process here, so the target thread id cannot pick a queue and a thread
            // message is queued with no window. Waking the pump is the part callers depend on.
            Win32kHelper.PostMessage(Instance, 0, Message, WParam, LParam);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
