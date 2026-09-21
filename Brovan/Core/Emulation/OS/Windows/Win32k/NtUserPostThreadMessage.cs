using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserPostThreadMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint TargetThreadId = (uint)Instance.WinHelper.GetArg(0);
            uint Message = (uint)Instance.WinHelper.GetArg(1);
            ulong WParam = Instance.WinHelper.GetArg(2);
            ulong LParam = Instance.WinHelper.GetArg(3);

            if ((Message & 0xFFFE0000u) != 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (TargetThreadId == 0
                || !Instance.Threads.TryGetValue(TargetThreadId, out EmulatedThread Target)
                || Target == null
                || Target.State == EmulatedThreadState.Terminated)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_THREAD_ID);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.PostThreadMessage(Instance, TargetThreadId, Message, WParam, LParam);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
