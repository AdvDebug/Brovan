using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetMessagePos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            ulong Position = State == null ? 0 : WinSysHelper.PackCoordinates(State.LastMessageX, State.LastMessageY);

            Instance.SetRawSyscallReturn(Position);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
