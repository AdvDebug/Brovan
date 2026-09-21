using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateCompatibleBitmap : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Width = unchecked((int)Instance.WinHelper.GetArg32(1));
            int Height = unchecked((int)Instance.WinHelper.GetArg32(2));

            ulong Bitmap = Win32kHelper.CreateCompatibleBitmap(Instance, Hdc, Width, Height);

            Instance.SetLastWinError(Bitmap == 0 ? Win32kHelper.ERROR_INVALID_PARAMETER : Win32kHelper.ERROR_SUCCESS);
            Instance.SetRawSyscallReturn(Bitmap);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
