using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserAttachThreadInput : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ThreadId = (uint)Instance.WinHelper.GetArg(0);
            uint TargetThreadId = (uint)Instance.WinHelper.GetArg(1);
            bool Attach = Instance.WinHelper.GetArg32(2) != 0;

            // NT: both threads must be live, and a thread cannot attach to itself.
            if (ThreadId == TargetThreadId || !IsLiveThread(Instance, ThreadId) || !IsLiveThread(Instance, TargetThreadId)
                || !Win32kHelper.AttachThreadInput(Instance, ThreadId, TargetThreadId, Attach))
            {
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsLiveThread(BinaryEmulator Instance, uint ThreadId)
        {
            return Instance.Threads.TryGetValue(ThreadId, out EmulatedThread Thread) && Thread.State != EmulatedThreadState.Terminated;
        }
    }
}
