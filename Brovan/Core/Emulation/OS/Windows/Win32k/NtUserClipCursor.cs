using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserClipCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong RectPtr = Instance.WinHelper.GetArg(0);

            if (RectPtr == 0)
            {
                Win32kHelper.ClearCursorClip(Instance);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(RectPtr, 16))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Left = (int)Instance.ReadMemoryUInt(RectPtr);
            int Top = (int)Instance.ReadMemoryUInt(RectPtr + 4);
            int Right = (int)Instance.ReadMemoryUInt(RectPtr + 8);
            int Bottom = (int)Instance.ReadMemoryUInt(RectPtr + 12);

            Win32kHelper.SetCursorClip(Instance, Left, Top, Right, Bottom);

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
