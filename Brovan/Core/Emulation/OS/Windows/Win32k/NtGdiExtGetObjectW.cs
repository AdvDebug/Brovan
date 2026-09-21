using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtGetObjectW : IWinSyscall
    {
        private const int Bitmap64Size = 0x20;
        private const int Bitmap32Size = 0x18;
        private const int DibSection64Size = 0x68;
        private const int DibSection32Size = 0x54;
        private const int BitmapInfoHeaderSize = 0x28;
        private const int LogPenSize = 0x10;
        private const int LogBrush64Size = 0x10;

        // lbHatch is a ULONG_PTR, so LOGBRUSH loses its tail padding on x86.
        private const int LogBrush32Size = 0x0C;
        private const uint BiRgb = 0;

        private const uint PsSolid = 0;
        private const uint BsSolid = 0;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.GetArg(0);
            int Count = unchecked((int)Instance.WinHelper.GetArg32(1));
            ulong OutBuffer = Instance.WinHelper.GetArg(2);

            bool IsBitmap = Win32kHelper.TryGetBitmap(Instance, Handle, out Win32kBitmap Bitmap);
            Win32kPenBrush PenBrush = default;
            bool IsPenBrush = false;

            if (!IsBitmap)
                IsPenBrush = Win32kHelper.TryGetPenBrush(Instance, Handle, out PenBrush);

            if (!IsBitmap && !IsPenBrush)
                return Fail(Instance);

            bool Wide = Instance.WinHelper.PointerSize == 8;
            int BitmapSize = Wide ? Bitmap64Size : Bitmap32Size;

            // A DIB section answers with the longer form only when the caller asked for all of it.
            bool AsDibSection = IsBitmap && Bitmap.DibSection && Count >= (Wide ? DibSection64Size : DibSection32Size);

            int Size = IsBitmap
                ? (AsDibSection ? (Wide ? DibSection64Size : DibSection32Size) : BitmapSize)
                : (PenBrush.IsPen ? LogPenSize : (Wide ? LogBrush64Size : LogBrush32Size));

            if (OutBuffer == 0)
            {
                int Natural = IsBitmap && Bitmap.DibSection ? (Wide ? DibSection64Size : DibSection32Size) : Size;
                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn((ulong)Natural);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Count < Size || !Instance.IsRegionMapped(OutBuffer, (ulong)Size))
                return Fail(Instance);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size).Slice(0, Size);
            Buffer.Clear();

            if (IsBitmap)
                WriteBitmap(Buffer, Bitmap, Wide, AsDibSection, BitmapSize);
            else
                WritePenBrush(Buffer, PenBrush);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Instance.WriteMemory(OutBuffer, Buffer) ? (ulong)Size : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Fail(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteBitmap(Span<byte> Buffer, in Win32kBitmap Bitmap, bool Wide, bool AsDibSection, int BitmapSize)
        {
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), Bitmap.Width);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x08, 4), Bitmap.Height);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x0C, 4), Bitmap.Stride);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x10, 2), Bitmap.Planes);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x12, 2), Bitmap.BitsPerPixel);

            // Only a DIB section hands its pixels to the caller; a device-dependent bitmap reports no bits.
            if (Bitmap.DibSection)
            {
                if (Wide)
                    BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), Bitmap.BitsAddress);
                else
                    BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14, 4), (uint)Bitmap.BitsAddress);
            }

            if (!AsDibSection)
                return;

            Span<byte> Header = Buffer.Slice(BitmapSize, BitmapInfoHeaderSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x00, 4), BitmapInfoHeaderSize);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x04, 4), Bitmap.Width);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(0x08, 4), Bitmap.TopDown ? -Bitmap.Height : Bitmap.Height);
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(0x0C, 2), Bitmap.Planes);
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(0x0E, 2), Bitmap.BitsPerPixel);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x10, 4), BiRgb);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x14, 4), Bitmap.BitsSize);
        }

        private static void WritePenBrush(Span<byte> Buffer, in Win32kPenBrush PenBrush)
        {
            if (PenBrush.IsPen)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), PsSolid);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), PenBrush.PenWidth);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x0C, 4), PenBrush.ColorRef);
                return;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), BsSolid);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), PenBrush.ColorRef);
        }
    }
}
