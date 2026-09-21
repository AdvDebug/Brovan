using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDCforBitmap : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong BitmapHandle = Instance.WinHelper.GetArg(0);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.FindDcForBitmap(Instance, BitmapHandle));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
