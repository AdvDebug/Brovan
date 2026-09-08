using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetClipCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong RectPtr = Instance.WinHelper.GetArg(0);

            if (RectPtr == 0 || !Instance.IsRegionMapped(RectPtr, 16))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // An unclipped cursor reports the whole virtual screen, not an empty rectangle.
            if (!Win32kHelper.TryGetCursorClip(Instance, out int Left, out int Top, out int Right, out int Bottom))
            {
                Left = 0;
                Top = 0;
                Right = HostDisplayMetrics.ScreenWidth;
                Bottom = HostDisplayMetrics.ScreenHeight;
            }

            Instance._emulator.WriteMemory(RectPtr, (ulong)(uint)Left, 4);
            Instance._emulator.WriteMemory(RectPtr + 4, (ulong)(uint)Top, 4);
            Instance._emulator.WriteMemory(RectPtr + 8, (ulong)(uint)Right, 4);
            Instance._emulator.WriteMemory(RectPtr + 12, (ulong)(uint)Bottom, 4);

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
