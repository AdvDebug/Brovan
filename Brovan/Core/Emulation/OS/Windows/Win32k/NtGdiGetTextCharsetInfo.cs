using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextCharsetInfo : IWinSyscall
    {
        private const uint AnsiCharset = 0;
        private const int FontSignatureSize = 24;
        private const uint BasicLatinRangeBit = 1;
        private const uint Latin1CodePageBit = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong SignaturePtr = Instance.WinHelper.GetArg(1);

            if (!Win32kHelper.IsKnownDc(Instance, Hdc))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn(uint.MaxValue);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // FONTSIGNATURE is four unicode subset masks then two code page masks.
            if (SignaturePtr != 0)
            {
                if (!Instance.WinHelper.WriteZeroMemory(SignaturePtr, FontSignatureSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(SignaturePtr, BasicLatinRangeBit, 4);
                Instance._emulator.WriteMemory(SignaturePtr + 16, Latin1CodePageBit, 4);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(AnsiCharset);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
