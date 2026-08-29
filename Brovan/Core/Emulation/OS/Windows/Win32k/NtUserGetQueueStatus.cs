using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetQueueStatus : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Flags = (uint)Instance.WinHelper.GetArg(0);
            uint Bits = Win32kHelper.GetQueuedWakeBits(Instance, Flags);

            // The low half should be only what arrived since the last call, which the queue does not record.
            Instance.SetRawSyscallReturn((Bits << 16) | Bits);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
