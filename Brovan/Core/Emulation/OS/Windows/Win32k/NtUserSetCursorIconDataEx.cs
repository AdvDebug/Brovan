using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetCursorIconDataEx : IWinSyscall
    {
        // CURSORDATA, which CreateIconIndirect fills in and hands to win32k. WOW64 user32 uses the same layout.
        private const int CursorDataSize = 0x88;

        private const int ResourceTypeOffset = 0x10;
        private const int FlagsOffset = 0x14;
        private const int HotspotOffset = 0x1C;
        private const int MaskBitmapOffset = 0x20;
        private const int ColorBitmapOffset = 0x28;
        private const int BppOffset = 0x50;
        private const int WidthOffset = 0x54;
        private const int HeightOffset = 0x58;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Cursor = Instance.WinHelper.GetArg(0);
            ulong DataPtr = Instance.WinHelper.GetArg(3);

            if (Cursor == 0 || DataPtr == 0 || !Instance.IsRegionMapped(DataPtr, CursorDataSize))
                return Fail(Instance);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(CursorDataSize).Slice(0, CursorDataSize);
            if (!Instance.ReadMemory(DataPtr, Buffer))
                return Fail(Instance);

            Win32kHelper.Win32kCursorIcon Data = new()
            {
                ResourceType = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(ResourceTypeOffset, 2)),
                Flags = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(FlagsOffset, 4)),
                HotspotX = BinaryPrimitives.ReadInt16LittleEndian(Buffer.Slice(HotspotOffset, 2)),
                HotspotY = BinaryPrimitives.ReadInt16LittleEndian(Buffer.Slice(HotspotOffset + 2, 2)),
                MaskBitmap = BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(MaskBitmapOffset, 8)),
                ColorBitmap = BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(ColorBitmapOffset, 8)),
                BitsPerPixel = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(BppOffset, 4)),
                Width = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(WidthOffset, 4)),
                Height = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(HeightOffset, 4)),
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

        private static NTSTATUS Fail(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
