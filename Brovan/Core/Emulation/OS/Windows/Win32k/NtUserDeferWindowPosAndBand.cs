using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDeferWindowPosAndBand : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DeferHandle = Instance.WinHelper.GetArg(0);

            Win32kHelper.Win32kDeferredWindowPos Position = new Win32kHelper.Win32kDeferredWindowPos
            {
                Hwnd = Instance.WinHelper.GetArg(1),
                InsertAfter = Instance.WinHelper.GetArg(2),
                X = unchecked((int)Instance.WinHelper.GetArg(3)),
                Y = unchecked((int)Instance.WinHelper.GetArg(4)),
                Width = unchecked((int)Instance.WinHelper.GetArg(5)),
                Height = unchecked((int)Instance.WinHelper.GetArg(6)),
                Flags = (uint)Instance.WinHelper.GetArg(7),
            };

            bool Added = Win32kHelper.DeferWindowPos(Instance, DeferHandle, Position);

            Instance.SetLastWinError(Added ? 0u : Win32kHelper.ERROR_INVALID_HANDLE);
            Instance.SetRawSyscallReturn(Added ? DeferHandle : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
