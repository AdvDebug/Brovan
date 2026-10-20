using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetQueueStatusReadonly : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ushort Flags = (ushort)Instance.WinHelper.GetArg(0);
            Instance.SetRawSyscallReturn(Win32kHelper.GetQueueStatus(Instance, Flags));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
