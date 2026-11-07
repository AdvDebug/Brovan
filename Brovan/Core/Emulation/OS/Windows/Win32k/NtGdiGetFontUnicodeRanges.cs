using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetFontUnicodeRanges : IWinSyscall
    {
        // A GLYPHSET header and one WCRANGE for each of the 65536 code units.
        private const int MaxGlyphSetBytes = 16 + 4 * 0x10000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong GlyphSetPtr = Instance.WinHelper.GetArg(1);

            Instance.SetRawSyscallReturn(Read(Instance, Hdc, GlyphSetPtr));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint Read(BinaryEmulator Instance, ulong Hdc, ulong GlyphSetPtr)
        {
            if (!Win32kHelper.IsKnownDc(Instance, Hdc) || !Win32kHelper.TryGetRealizedFont(Instance, Hdc, out ITextMetricsSupport Text, out IntPtr Font))
                return 0;

            if (GlyphSetPtr == 0)
                return Text.GetUnicodeRanges(Font, Span<byte>.Empty);

            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(MaxGlyphSetBytes).Slice(0, MaxGlyphSetBytes);
            uint Size = Text.GetUnicodeRanges(Font, Data);
            if (Size == 0 || Size > MaxGlyphSetBytes)
                return 0;

            return Instance.WriteMemory(GlyphSetPtr, Data.Slice(0, (int)Size)) ? Size : 0;
        }
    }
}
