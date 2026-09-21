using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRealizePalette : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);

            // Nothing maps on a display that is not palettised, so no entry changes.
            Instance.SetLastWinError(Win32kHelper.IsKnownDc(Instance, Hdc) ? 0u : Win32kHelper.ERROR_INVALID_HANDLE);
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
