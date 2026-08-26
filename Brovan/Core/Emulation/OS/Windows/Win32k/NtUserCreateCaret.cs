using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserCreateCaret : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Bitmap = Instance.WinHelper.GetArg(1);
            int Width = unchecked((int)Instance.WinHelper.GetArg(2));
            int Height = unchecked((int)Instance.WinHelper.GetArg(3));

            bool Created = Win32kHelper.CreateCaret(Instance, Hwnd, Bitmap, Width, Height);
            Instance.SetLastWinError(Created ? 0u : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Created);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
