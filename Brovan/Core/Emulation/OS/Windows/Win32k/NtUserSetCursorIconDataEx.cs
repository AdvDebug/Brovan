using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetCursorIconDataEx : IWinSyscall
    {
        // CURSORDATA, which CreateIconIndirect fills in and hands to win32k.
        private const int CursorData64Size = 0x88;
        private const int CursorData32Size = 0x54;

        private const int Flags64Offset = 0x14;
        private const int Hotspot64Offset = 0x18;
        private const int MaskBitmap64Offset = 0x20;
        private const int ColorBitmap64Offset = 0x28;
        private const int Bpp64Offset = 0x50;
        private const int Width64Offset = 0x54;
        private const int Height64Offset = 0x58;

        private const int Flags32Offset = 0x0C;
        private const int Hotspot32Offset = 0x10;
        private const int MaskBitmap32Offset = 0x14;
        private const int ColorBitmap32Offset = 0x18;
        private const int Bpp32Offset = 0x34;
        private const int Width32Offset = 0x38;
        private const int Height32Offset = 0x3C;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Cursor = Instance.WinHelper.GetArg(0);
            ulong DataPtr = Instance.WinHelper.GetArg(3);

            bool Wide = Instance.WinHelper.PointerSize == 8;
            int Size = Wide ? CursorData64Size : CursorData32Size;

            if (Cursor == 0 || DataPtr == 0 || !Instance.IsRegionMapped(DataPtr, (ulong)Size))
                return Fail(Instance);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size).Slice(0, Size);
            if (!Instance.ReadMemory(DataPtr, Buffer))
                return Fail(Instance);

            Win32kHelper.Win32kCursorIcon Data = new()
            {
                Flags = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(Wide ? Flags64Offset : Flags32Offset, 4)),
                HotspotX = BinaryPrimitives.ReadInt16LittleEndian(Buffer.Slice(Wide ? Hotspot64Offset : Hotspot32Offset, 2)),
                HotspotY = BinaryPrimitives.ReadInt16LittleEndian(Buffer.Slice((Wide ? Hotspot64Offset : Hotspot32Offset) + 2, 2)),
                MaskBitmap = ReadHandle(Buffer, Wide ? MaskBitmap64Offset : MaskBitmap32Offset, Wide),
                ColorBitmap = ReadHandle(Buffer, Wide ? ColorBitmap64Offset : ColorBitmap32Offset, Wide),
                BitsPerPixel = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(Wide ? Bpp64Offset : Bpp32Offset, 4)),
                Width = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(Wide ? Width64Offset : Width32Offset, 4)),
                Height = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(Wide ? Height64Offset : Height32Offset, 4)),
            };

            // The mask holds the AND and XOR images one above the other unless a colour bitmap is given.
            if ((Data.Width <= 0 || Data.Height <= 0) && Win32kHelper.TryGetBitmap(Instance, Data.MaskBitmap, out Win32kBitmap Mask))
            {
                Data.Width = Mask.Width;
                Data.Height = Data.ColorBitmap != 0 ? Mask.Height : Mask.Height / 2;
            }

            if (Data.Width <= 0 || Data.Height <= 0)
                return Fail(Instance);

            if (Data.BitsPerPixel == 0)
                Data.BitsPerPixel = Data.ColorBitmap != 0 ? 32u : 1u;

            Win32kHelper.SetCursorIconData(Instance, Cursor, Data);

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong ReadHandle(ReadOnlySpan<byte> Buffer, int Offset, bool Wide)
        {
            return Wide
                ? BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(Offset, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(Offset, 4));
        }

        private static NTSTATUS Fail(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
