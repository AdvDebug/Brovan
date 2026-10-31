using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSystemParametersInfoForDpi : IWinSyscall
    {
        private const uint SpiGetIconTitleLogFont = 0x001F;
        private const uint SpiGetNonClientMetrics = 0x0029;
        private const uint SpiGetIconMetrics = 0x002D;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Action = Instance.WinHelper.GetArg32(0);
            uint Size = Instance.WinHelper.GetArg32(1);
            ulong ParameterPtr = Instance.WinHelper.GetArg(2);
            uint Dpi = Instance.WinHelper.GetArg32(4);

            int Expected = Action switch
            {
                SpiGetNonClientMetrics => WinSysHelper.NonClientMetricsSize,
                SpiGetIconTitleLogFont => WinSysHelper.LogFontSize,
                SpiGetIconMetrics => WinSysHelper.IconMetricsSize,
                _ => 0,
            };

            if (Dpi == 0 || ParameterPtr == 0 || Expected == 0 || Size != (uint)Expected)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            // NT requires 4-byte alignment only for native x64 callers.
            if ((Instance.WinHelper.PointerSize == 8 && (ParameterPtr & 3) != 0)
                || Instance.WinHelper.ProbeForWrite(ParameterPtr, Size) != NTSTATUS.STATUS_SUCCESS)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            Span<byte> Buffer = stackalloc byte[WinSysHelper.NonClientMetricsSize];
            Buffer = Buffer.Slice(0, Expected);
            Buffer.Clear();
            if (!Instance.ReadMemory(ParameterPtr, Buffer.Slice(0, sizeof(uint))))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            // An invalid cbSize preserves that field and zeroes the remaining buffer.
            uint CbSize = BinaryPrimitives.ReadUInt32LittleEndian(Buffer);
            bool Filled = true;
            switch (Action)
            {
                case SpiGetNonClientMetrics when CbSize == WinSysHelper.NonClientMetricsSize:
                    Instance.WinHelper.WriteNonClientMetrics(Buffer, Dpi);
                    break;

                case SpiGetIconMetrics when CbSize == WinSysHelper.IconMetricsSize:
                    Instance.WinHelper.WriteIconMetrics(Buffer, Dpi);
                    break;

                case SpiGetIconTitleLogFont:
                    WinSysHelper.WriteSystemLogFont(Buffer, Instance.WinHelper.GetSystemFontHeight(Dpi));
                    break;

                default:
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Filled = false;
                    break;
            }

            if (!Instance.WriteMemory(ParameterPtr, Buffer))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            Instance.SetRawSyscallReturn(Filled ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
