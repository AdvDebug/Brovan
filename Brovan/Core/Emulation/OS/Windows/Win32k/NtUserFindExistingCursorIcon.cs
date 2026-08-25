using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserFindExistingCursorIcon : IWinSyscall
    {
        private const ulong ResourceTypeOffset = 8;
        private const uint ResourceTypeCursor = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ModuleName = Instance.WinHelper.GetArg(0);
            ulong ResourceName = Instance.WinHelper.GetArg(1);
            ulong Find = Instance.WinHelper.GetArg(2);
            _ = ModuleName;
            _ = ResourceName;

            bool Cursor = Find != 0
                && Instance.IsRegionMapped(Find + ResourceTypeOffset, 4)
                && Instance.ReadMemoryUInt(Find + ResourceTypeOffset) == ResourceTypeCursor;

            Instance.SetRawSyscallReturn(Cursor ? Win32kHelper.EnsureStockCursor(Instance) : 0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
