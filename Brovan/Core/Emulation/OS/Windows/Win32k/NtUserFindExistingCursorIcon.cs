using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserFindExistingCursorIcon : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ModuleName = Instance.WinHelper.GetArg(0);
            ulong ResourceName = Instance.WinHelper.GetArg(1);
            ulong CursorFind = Instance.WinHelper.GetArg(2);
            _ = ModuleName;
            _ = ResourceName;
            _ = CursorFind;

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
