using System;
using System.Buffers;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDIBitsInternal : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong BitmapHandle = Instance.WinHelper.GetArg(1);
            uint StartScan = (uint)Instance.WinHelper.GetArg(2);
            uint Scans = (uint)Instance.WinHelper.GetArg(3);
            ulong BitsAddress = Instance.WinHelper.GetArg(4);
            ulong HeaderAddress = Instance.WinHelper.GetArg(5);

            if (!Win32kHelper.TryGetBitmap(Instance, BitmapHandle, out Win32kBitmap Bitmap)
                || !Win32kHelper.TryReadDibHeader(Instance, HeaderAddress, out Win32kHelper.DibHeader Header))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (BitsAddress == 0)
            {
                bool Described = WriteHeader(Instance, HeaderAddress, Bitmap);
                Instance.SetLastWinError(Described ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(Described ? 1UL : 0UL);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Header.BitsPerPixel != 32 && Header.BitsPerPixel != 24)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Width = Math.Min(Header.Width, Bitmap.Width);
            int Available = Bitmap.Height > (int)StartScan ? Bitmap.Height - (int)StartScan : 0;
            int Rows = Math.Min((int)Scans, Available);
            if (Width <= 0 || Rows <= 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int BytesPerPixel = Header.BitsPerPixel / 8;
            int Stride = ((Header.Width * Header.BitsPerPixel + 31) / 32) * 4;
            if (!Instance.IsRegionMapped(BitsAddress, (ulong)((long)Stride * Rows)))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Count = Width * Rows;
            uint[] Pixels = ArrayPool<uint>.Shared.Rent(Count);
            byte[] LineBuffer = ArrayPool<byte>.Shared.Rent(Stride);
            int Written = 0;
            try
            {
                Span<uint> Block = Pixels.AsSpan(0, Count);
                if (!Win32kHelper.TryReadBitmapBlock(Instance, Bitmap, 0, (int)StartScan, Width, Rows, Block))
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Span<byte> Line = LineBuffer.AsSpan(0, Stride);

                for (int Row = 0; Row < Rows; Row++)
                {
                    Line.Clear();
                    ReadOnlySpan<uint> Source = Block.Slice(Row * Width, Width);

                    for (int Column = 0; Column < Width; Column++)
                    {
                        uint Pixel = Source[Column];
                        int Offset = Column * BytesPerPixel;
                        Line[Offset] = (byte)Pixel;
                        Line[Offset + 1] = (byte)(Pixel >> 8);
                        Line[Offset + 2] = (byte)(Pixel >> 16);
                    }

                    // The caller's rows follow its own header, bottom-up by default.
                    int TargetRow = Header.TopDown ? Row : Rows - 1 - Row;
                    if (!Instance.WriteMemory(BitsAddress + (ulong)((long)TargetRow * Stride), Line))
                        break;

                    Written++;
                }
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Pixels);
                ArrayPool<byte>.Shared.Return(LineBuffer);
            }

            WriteHeader(Instance, HeaderAddress, Bitmap);
            Instance.SetLastWinError(Written > 0 ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn((ulong)(uint)Written);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool WriteHeader(BinaryEmulator Instance, ulong HeaderAddress, in Win32kBitmap Bitmap)
        {
            if (!Instance.IsRegionMapped(HeaderAddress, Win32kHelper.BitmapInfoHeaderSize))
                return false;

            uint HeaderSize = Instance.ReadMemoryUInt(HeaderAddress);
            if (HeaderSize < Win32kHelper.BitmapInfoHeaderSize)
                return false;

            int Stride = ((Bitmap.Width * Bitmap.BitsPerPixel + 31) / 32) * 4;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Win32kHelper.BitmapInfoHeaderSize);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Win32kHelper.BitmapInfoHeaderSize);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), Bitmap.Width);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x08, 4), Bitmap.Height);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x0C, 2), Bitmap.Planes);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x0E, 2), Bitmap.BitsPerPixel);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10, 4), Win32kHelper.BI_RGB);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14, 4), (uint)((long)Stride * Bitmap.Height));

            return Instance.WriteMemory(HeaderAddress, Buffer);
        }
    }
}
