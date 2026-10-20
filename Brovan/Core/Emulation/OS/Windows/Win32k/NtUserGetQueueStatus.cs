using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetQueueStatus : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Flags = (uint)Instance.WinHelper.GetArg(0);
            Win32kQueuePort.DrainForMessages(Instance, Instance.CurrentThread?.ThreadId ?? 0, Flags);
            Instance.SetRawSyscallReturn(Win32kHelper.GetQueueStatus(Instance, Flags));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
