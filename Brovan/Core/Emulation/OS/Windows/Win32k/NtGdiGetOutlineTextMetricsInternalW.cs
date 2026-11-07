using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetOutlineTextMetricsInternalW : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint Size = (uint)Instance.WinHelper.GetArg(1);
            ulong BufferPtr = Instance.WinHelper.GetArg(2);
            ulong DiffPtr = Instance.WinHelper.GetArg(3);

            Instance.SetRawSyscallReturn(Read(Instance, Hdc, Size, BufferPtr, DiffPtr));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint Read(BinaryEmulator Instance, ulong Hdc, uint Size, ulong BufferPtr, ulong DiffPtr)
        {
            if (BufferPtr == 0)
                Size = 0;

            if (Size > Win32kHelper.MaxGdiBufferBytes)
                return 0;

            if (!Win32kHelper.IsKnownDc(Instance, Hdc))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                return 0;
            }

            if (!Win32kHelper.TryGetRealizedFont(Instance, Hdc, out ITextMetricsSupport Text, out IntPtr Font)
                || !Text.GetOutlineTextMetrics(Font, out OutlineTextMetricsData Metrics))
                return 0;

            int PointerSize = Instance.WinHelper.PointerSize;
            uint Fixed = (uint)(OutlineTextMetricsData.HeadSize + 4 * PointerSize);
            uint Full = Fixed + (uint)Metrics.Names.Length;

            // A buffer that holds the structure but not the names gets nothing.
            uint Result = Size == 0 ? Full : Size <= Fixed ? Size : Size < Full ? 0 : Full;
            if (Result == 0)
                return 0;

            if (DiffPtr != 0 && !Instance.WinHelper.WriteUInt64(DiffPtr, Metrics.Diff))
                return 0;

            if (Size == 0)
                return Result;

            Span<byte> Image = Instance.WinHelper.Shared.GetSpan(Full).Slice(0, (int)Full);
            Metrics.Head.CopyTo(Image);
            BinaryPrimitives.WriteUInt32LittleEndian(Image, Full);

            bool WithNames = Size >= Full;
            Span<byte> NameFields = Image.Slice(OutlineTextMetricsData.HeadSize);
            for (int Index = 0; Index < Metrics.NameOffsets.Length; Index++)
            {
                uint Offset = Metrics.NameOffsets[Index];
                ulong Value = !WithNames || Offset == uint.MaxValue ? 0 : Fixed + Offset;
                WinSysHelper.WritePointerField(NameFields, Index, (uint)PointerSize, Value);
            }

            Metrics.Names.CopyTo(Image.Slice((int)Fixed));

            // x64 NT writes the whole buffer. The WOW64 thunk copies only the structure it converted.
            ReadOnlySpan<byte> Written = Image.Slice(0, (int)Math.Min(Size, Full));
            bool Wrote = PointerSize == 8
                ? Instance.WinHelper.WritePadded(BufferPtr, Size, Written)
                : Instance.WriteMemory(BufferPtr, Written);

            return Wrote ? Result : 0;
        }
    }
}
