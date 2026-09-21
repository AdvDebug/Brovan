using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCombineRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Destination = Instance.WinHelper.GetArg(0);
            ulong SourceA = Instance.WinHelper.GetArg(1);
            ulong SourceB = Instance.WinHelper.GetArg(2);
            int Mode = unchecked((int)Instance.WinHelper.GetArg(3));

            if (!Win32kHelper.TryReadRegionRect(Instance, SourceA, out int ALeft, out int ATop, out int ARight, out int ABottom))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryReadRegionRect(Instance, SourceB, out int BLeft, out int BTop, out int BRight, out int BBottom))
            {
                BLeft = 0;
                BTop = 0;
                BRight = 0;
                BBottom = 0;
            }

            int Result = Win32kHelper.CombineRegionRects(Mode, ALeft, ATop, ARight, ABottom, BLeft, BTop, BRight, BBottom,
                out int Left, out int Top, out int Right, out int Bottom);

            if (!Win32kHelper.TryWriteRegionRect(Instance, Destination, Left, Top, Right, Bottom))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn((ulong)Win32kHelper.RegionError);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn((ulong)Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
