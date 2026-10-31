using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserIsTopLevelWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Instance.WinHelper.GetArg(0));
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            Instance.SetBooleanSyscallReturn(Window.ParentHwnd == 0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
