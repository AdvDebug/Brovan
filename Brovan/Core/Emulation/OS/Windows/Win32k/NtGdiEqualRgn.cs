using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiEqualRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong First = Instance.WinHelper.GetArg(0);
            ulong Second = Instance.WinHelper.GetArg(1);

            bool Equal = Win32kHelper.TryReadRegionRect(Instance, First, out int ALeft, out int ATop, out int ARight, out int ABottom)
                && Win32kHelper.TryReadRegionRect(Instance, Second, out int BLeft, out int BTop, out int BRight, out int BBottom)
                && ALeft == BLeft && ATop == BTop && ARight == BRight && ABottom == BBottom;

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Equal ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
