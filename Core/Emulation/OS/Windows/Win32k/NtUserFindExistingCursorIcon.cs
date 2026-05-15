using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserFindExistingCursorIcon : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ModuleName = Instance.WinHelper.GetArg64(0);
            ulong ResourceName = Instance.WinHelper.GetArg64(1);
            ulong CursorFind = Instance.WinHelper.GetArg64(2);
            _ = ModuleName;
            _ = ResourceName;
            _ = CursorFind;

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
