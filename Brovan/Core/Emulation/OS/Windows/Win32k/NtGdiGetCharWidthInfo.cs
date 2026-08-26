using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Brovan draws every glyph inside its advance width, so both side bearings are genuinely zero.
    internal class NtGdiGetCharWidthInfo : IWinSyscall
    {
        private const int CharWidthInfoSize = 12;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong InfoPtr = Instance.WinHelper.GetArg(1);

            if (InfoPtr == 0 || !Win32kHelper.IsKnownDc(Instance, Hdc))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WinHelper.WriteZeroMemory(InfoPtr, CharWidthInfoSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
