using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateDIBitmapInternal : IWinSyscall
    {
        private const int BitmapInfoHeaderSize = 40;
        private const uint CbmInit = 0x04;
        private const uint BI_RGB = 0;
        private const uint BI_BITFIELDS = 3;
        private const ushort MonochromeBitsPerPixel = 1;
        private const ushort DisplayBitsPerPixel = 32;
        private const int RowCopyChunkBytes = 0x10000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Width = unchecked((int)Instance.WinHelper.GetArg32(1));
            int Height = unchecked((int)Instance.WinHelper.GetArg32(2));
            uint Init = Instance.WinHelper.GetArg32(3);
            ulong InitialBits = Instance.WinHelper.GetArg(4);
            ulong HeaderAddress = Instance.WinHelper.GetArg(5);

            if (Width <= 0 || Height <= 0)
                return Fail(Instance);

            int SourceWidth = 0;
            int SourceHeight = 0;
            ushort SourceBitsPerPixel = 0;
            bool Initialise = false;

            if ((Init & CbmInit) != 0 && InitialBits != 0)
                Initialise = TryReadHeader(Instance, HeaderAddress, out SourceWidth, out SourceHeight, out SourceBitsPerPixel);

            ushort BitsPerPixel = Initialise ? SourceBitsPerPixel : (Hdc == 0 ? MonochromeBitsPerPixel : DisplayBitsPerPixel);

            ulong Handle = Win32kHelper.CreateBitmap(Instance, Width, Height, 1, BitsPerPixel, false, false);
            if (Handle == 0 || !Win32kHelper.TryGetBitmap(Instance, Handle, out Win32kBitmap Bitmap))
                return Fail(Instance);

            if (Initialise && !CopyRows(Instance, Bitmap, InitialBits, SourceWidth, SourceHeight, SourceBitsPerPixel))
            {
                Win32kHelper.RemoveBitmap(Instance, Handle);
                Instance.WinHelper.FreeGdiHandle(Handle);
                return Fail(Instance);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Fail(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        /// <summary>
        /// The source DIB pads its scanlines to a DWORD while the bitmap created here pads to a WORD, so the
        /// initial bits have to be moved a row at a time even when both sides share a pixel format.
        /// </summary>
        private static bool CopyRows(BinaryEmulator Instance, in Win32kBitmap Bitmap, ulong SourceAddress, int SourceWidth, int SourceHeight, ushort SourceBitsPerPixel)
        {
            int SourceStride = Win32kHelper.GetBitmapStride(SourceWidth, 1, SourceBitsPerPixel, true);
            if (SourceStride == 0)
                return false;

            int Rows = Math.Min(SourceHeight, Bitmap.Height);
            int RowBytes = Math.Min(SourceStride, Bitmap.Stride);
            if (Rows <= 0 || RowBytes <= 0 || !Instance.IsRegionMapped(SourceAddress, (ulong)SourceStride * (ulong)Rows))
                return false;

            Span<byte> Row = Instance.WinHelper.Shared.GetSpan((ulong)Math.Min(RowBytes, RowCopyChunkBytes));
            for (int y = 0; y < Rows; y++)
            {
                ulong SourceRow = SourceAddress + (ulong)((long)y * SourceStride);
                ulong TargetRow = Bitmap.BitsAddress + (ulong)((long)y * Bitmap.Stride);

                for (int Copied = 0; Copied < RowBytes;)
                {
                    int Size = Math.Min(RowCopyChunkBytes, RowBytes - Copied);
                    Span<byte> Slice = Row.Slice(0, Size);
                    if (!Instance.ReadMemory(SourceRow + (ulong)Copied, Slice, (uint)Size))
                        return false;

                    if (!Instance.WriteMemory(TargetRow + (ulong)Copied, Slice))
                        return false;

                    Copied += Size;
                }
            }

            return true;
        }

        private static bool TryReadHeader(BinaryEmulator Instance, ulong Address, out int Width, out int Height, out ushort BitsPerPixel)
        {
            Width = 0;
            Height = 0;
            BitsPerPixel = 0;

            if (Address == 0 || !Instance.IsRegionMapped(Address, BitmapInfoHeaderSize))
                return false;

            Span<byte> Header = Instance.WinHelper.Shared.GetSpan(BitmapInfoHeaderSize);
            if (!Instance.ReadMemory(Address, Header, BitmapInfoHeaderSize))
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x00, 4)) < BitmapInfoHeaderSize)
                return false;

            uint Compression = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x10, 4));
            if (Compression != BI_RGB && Compression != BI_BITFIELDS)
                return false;

            if (BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0C, 2)) != 1)
                return false;

            Width = BinaryPrimitives.ReadInt32LittleEndian(Header.Slice(0x04, 4));
            int RawHeight = BinaryPrimitives.ReadInt32LittleEndian(Header.Slice(0x08, 4));
            Height = RawHeight < 0 ? -RawHeight : RawHeight;
            BitsPerPixel = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0E, 2));
            return Width > 0 && Height > 0 && BitsPerPixel != 0;
        }
    }
}
