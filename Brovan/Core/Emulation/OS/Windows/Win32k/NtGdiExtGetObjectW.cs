using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtGetObjectW : IWinSyscall
    {
        private const int Bitmap64Size = 0x20;
        private const int LogPen64Size = 0x10;
        private const int LogBrush64Size = 0x10;

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

            int Size = IsBitmap ? Bitmap64Size : (PenBrush.IsPen ? LogPen64Size : LogBrush64Size);

            if (OutBuffer == 0)
            {
                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn((ulong)Size);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Count < Size || !Instance.IsRegionMapped(OutBuffer, (ulong)Size))
                return Fail(Instance);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size).Slice(0, Size);
            Buffer.Clear();

            if (IsBitmap)
                WriteBitmap(Buffer, Bitmap);
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

        private static void WriteBitmap(Span<byte> Buffer, in Win32kBitmap Bitmap)
        {
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), Bitmap.Width);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x08, 4), Bitmap.Height);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x0C, 4), Bitmap.Stride);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x10, 2), Bitmap.Planes);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x12, 2), Bitmap.BitsPerPixel);

            // Only a DIB section hands its pixels to the caller; a device-dependent bitmap reports no bits.
            if (Bitmap.DibSection)
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), Bitmap.BitsAddress);
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
