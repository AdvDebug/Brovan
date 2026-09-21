using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetIconSize : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Icon = Instance.WinHelper.GetArg(0);
            ulong WidthPtr = Instance.WinHelper.GetArg(2);
            ulong HeightPtr = Instance.WinHelper.GetArg(3);

            if (!Win32kHelper.TryGetCursorIcon(Instance, Icon, out Win32kHelper.Win32kCursorIcon Data)
                || WidthPtr == 0 || HeightPtr == 0
                || !Instance.WinHelper.WriteUInt32(WidthPtr, (uint)Data.Width)
                || !Instance.WinHelper.WriteUInt32(HeightPtr, (uint)Data.Height))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
