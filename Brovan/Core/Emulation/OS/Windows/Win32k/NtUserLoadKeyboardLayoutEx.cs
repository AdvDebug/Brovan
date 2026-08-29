using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserLoadKeyboardLayoutEx : IWinSyscall
    {
        private const int KlidArgument = 5;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // user32 hands the KLID down as a UNICODE_STRING, and the layout it names has to be installed.
            if (!Instance.WinHelper.TryReadUnicodeString(Instance.WinHelper.GetArg(KlidArgument), out string Klid, out _)
                || !Win32kHelper.TryParseKlid(Klid, out uint Value)
                || !Win32kHelper.IsInstalledKeyboardLayout(Instance, Klid))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.KeyboardLayoutFromKlid(Value));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
