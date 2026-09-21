using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateHalftonePalette : IWinSyscall
    {
        private const byte PaletteHandleType = 0x08;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.AllocateGdiHandle(PaletteHandleType);

            Instance.SetLastWinError(Handle == 0 ? Win32kHelper.ERROR_INVALID_PARAMETER : Win32kHelper.ERROR_SUCCESS);
            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
