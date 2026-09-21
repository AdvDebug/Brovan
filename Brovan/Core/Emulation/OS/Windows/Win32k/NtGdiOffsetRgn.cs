using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiOffsetRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Region = Instance.WinHelper.GetArg(0);
            int OffsetX = unchecked((int)Instance.WinHelper.GetArg(1));
            int OffsetY = unchecked((int)Instance.WinHelper.GetArg(2));

            if (!Win32kHelper.TryReadRegionRect(Instance, Region, out int Left, out int Top, out int Right, out int Bottom))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Empty = Right <= Left || Bottom <= Top;
            if (!Empty)
            {
                Left += OffsetX;
                Right += OffsetX;
                Top += OffsetY;
                Bottom += OffsetY;
            }

            Win32kHelper.TryWriteRegionRect(Instance, Region, Left, Top, Right, Bottom);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)(Empty ? Win32kHelper.RegionNull : Win32kHelper.RegionSimple));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
