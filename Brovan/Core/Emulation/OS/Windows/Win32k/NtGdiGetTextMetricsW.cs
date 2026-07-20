using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextMetricsW : IWinSyscall
    {
        private const int TextMetricWSize = 60;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.GetArg(0);
            ulong BufferPtr = Instance.WinHelper.GetArg(1);
            uint BufferSize = (uint)Instance.WinHelper.GetArg(2);

            if (BufferPtr == 0 || BufferSize < TextMetricWSize)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            TextMetricsData Metrics;
            if (!Instance.WinHelper.GetTextMetrics(out Metrics))
            {
                Metrics = new TextMetricsData
                {
                    Height = 16,
                    Ascent = 12,
                    Descent = 4,
                    AveCharWidth = 8,
                    MaxCharWidth = 16,
                    Weight = 400,
                    DigitizedAspectX = 96,
                    DigitizedAspectY = 96,
                    FirstChar = 0x20,
                    LastChar = 0xFF,
                    DefaultChar = 0x20,
                    BreakChar = 0x20,
                    PitchAndFamily = 0x01,
                };
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(TextMetricWSize);
            Buffer.Clear();
            WriteI32(Buffer, 0x00, Metrics.Height);
            WriteI32(Buffer, 0x04, Metrics.Ascent);
            WriteI32(Buffer, 0x08, Metrics.Descent);
            WriteI32(Buffer, 0x0C, Metrics.InternalLeading);
            WriteI32(Buffer, 0x10, Metrics.ExternalLeading);
            WriteI32(Buffer, 0x14, Metrics.AveCharWidth);
            WriteI32(Buffer, 0x18, Metrics.MaxCharWidth);
            WriteI32(Buffer, 0x1C, Metrics.Weight);
            WriteI32(Buffer, 0x20, Metrics.Overhang);
            WriteI32(Buffer, 0x24, Metrics.DigitizedAspectX);
            WriteI32(Buffer, 0x28, Metrics.DigitizedAspectY);
            WriteU16(Buffer, 0x2C, Metrics.FirstChar);
            WriteU16(Buffer, 0x2E, Metrics.LastChar);
            WriteU16(Buffer, 0x30, Metrics.DefaultChar);
            WriteU16(Buffer, 0x32, Metrics.BreakChar);
            Buffer[0x34] = Metrics.Italic;
            Buffer[0x35] = Metrics.Underlined;
            Buffer[0x36] = Metrics.StruckOut;
            Buffer[0x37] = Metrics.PitchAndFamily;
            Buffer[0x38] = Metrics.CharSet;

            if (!Instance.WriteMemory(BufferPtr, Buffer.Slice(0, TextMetricWSize)))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteI32(Span<byte> Buffer, int Offset, int Value)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        private static void WriteU16(Span<byte> Buffer, int Offset, ushort Value)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(Offset, 2), Value);
        }
    }
}
