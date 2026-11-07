using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetGlyphOutline : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ushort Code = (ushort)Instance.WinHelper.GetArg(1);
            uint Format = (uint)Instance.WinHelper.GetArg(2);
            ulong MetricsPtr = Instance.WinHelper.GetArg(3);
            uint Size = (uint)Instance.WinHelper.GetArg(4);
            ulong BufferPtr = Instance.WinHelper.GetArg(5);
            ulong MatrixPtr = Instance.WinHelper.GetArg(6);
            bool IgnoreRotation = (uint)Instance.WinHelper.GetArg(7) != 0;

            Instance.SetRawSyscallReturn(Read(Instance, Hdc, Code, Format, MetricsPtr, Size, BufferPtr, MatrixPtr, IgnoreRotation));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint Read(BinaryEmulator Instance, ulong Hdc, ushort Code, uint Format, ulong MetricsPtr, uint Size,
            ulong BufferPtr, ulong MatrixPtr, bool IgnoreRotation)
        {
            if (Size > Win32kHelper.MaxGdiBufferBytes)
                return Win32kHelper.GdiError;

            Mat2Data Matrix = default;
            if (!Instance.ReadMemory(MatrixPtr, MemoryMarshal.AsBytes(new Span<Mat2Data>(ref Matrix))))
                return Win32kHelper.GdiError;

            if (!Win32kHelper.IsKnownDc(Instance, Hdc) || !Win32kHelper.TryGetRealizedFont(Instance, Hdc, out ITextMetricsSupport Text, out IntPtr Font))
                return Win32kHelper.GdiError;

            uint Needed = Text.GetGlyphOutline(Font, Code, Format, Matrix, IgnoreRotation, out GlyphMetricsData Metrics, Span<byte>.Empty);
            if (Needed == Win32kHelper.GdiError)
                return Win32kHelper.GdiError;

            uint Result = Needed;
            if (Size != 0)
            {
                if (Needed > Size || BufferPtr == 0)
                    return Win32kHelper.GdiError;

                Result = Fill(Instance, Text, Font, Code, Format, Matrix, IgnoreRotation, Needed, Size, BufferPtr, out Metrics);
                if (Result == Win32kHelper.GdiError)
                    return Win32kHelper.GdiError;
            }

            if (!Instance.WriteMemory(MetricsPtr, MemoryMarshal.AsBytes(new ReadOnlySpan<GlyphMetricsData>(in Metrics))))
                return Win32kHelper.GdiError;

            return Result;
        }

        // NT writes the whole buffer, the glyph's data and then zeros.
        private static uint Fill(BinaryEmulator Instance, ITextMetricsSupport Text, IntPtr Font, ushort Code, uint Format, in Mat2Data Matrix,
            bool IgnoreRotation, uint Needed, uint Size, ulong BufferPtr, out GlyphMetricsData Metrics)
        {
            using CallBuffer Buffer = new CallBuffer((int)Needed);
            uint Written = Text.GetGlyphOutline(Font, Code, Format, Matrix, IgnoreRotation, out Metrics, Buffer.Span);
            if (Written == Win32kHelper.GdiError || Written > Needed || !Instance.WinHelper.WritePadded(BufferPtr, Size, Buffer.Span))
                return Win32kHelper.GdiError;

            return Written;
        }
    }
}
