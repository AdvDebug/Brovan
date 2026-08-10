using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateDIBSection : IWinSyscall
    {
        private const int BitmapCoreHeaderSize = 12;
        private const int BitmapInfoHeaderSize = 40;
        private const uint BI_RGB = 0;
        private const uint BI_BITFIELDS = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong SectionHandle = Instance.WinHelper.GetArg(1);
            ulong HeaderAddress = Instance.WinHelper.GetArg(3);
            ulong BitsPointerOut = Instance.WinHelper.GetArg(8);

            if (!TryReadHeader(Instance, HeaderAddress, out int Width, out int Height, out ushort Planes, out ushort BitsPerPixel, out uint Compression)
                || SectionHandle != 0
                || Planes != 1
                || (Compression != BI_RGB && Compression != BI_BITFIELDS))
            {
                return Fail(Instance, BitsPointerOut);
            }

            bool TopDown = Height < 0;
            int AbsoluteHeight = TopDown ? -Height : Height;

            ulong Handle = Win32kHelper.CreateBitmap(Instance, Width, AbsoluteHeight, Planes, BitsPerPixel, true, TopDown);
            if (Handle == 0 || !Win32kHelper.TryGetBitmap(Instance, Handle, out Win32kBitmap Bitmap))
                return Fail(Instance, BitsPointerOut);

            if (BitsPointerOut == 0 || !Instance.IsRegionMapped(BitsPointerOut, 8)
                || !Instance._emulator.WriteMemory(BitsPointerOut, Bitmap.BitsAddress, 8))
            {
                Win32kHelper.RemoveBitmap(Instance, Handle);
                Instance.WinHelper.FreeGdiHandle(Handle);
                return Fail(Instance, 0);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Fail(BinaryEmulator Instance, ulong BitsPointerOut)
        {
            if (BitsPointerOut != 0 && Instance.IsRegionMapped(BitsPointerOut, 8))
                Instance._emulator.WriteMemory(BitsPointerOut, 0UL, 8);

            Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryReadHeader(BinaryEmulator Instance, ulong Address, out int Width, out int Height, out ushort Planes, out ushort BitsPerPixel, out uint Compression)
        {
            Width = 0;
            Height = 0;
            Planes = 0;
            BitsPerPixel = 0;
            Compression = BI_RGB;

            if (Address == 0 || !Instance.IsRegionMapped(Address, BitmapCoreHeaderSize))
                return false;

            uint HeaderSize = Instance.ReadMemoryUInt(Address);
            int ReadSize = HeaderSize == BitmapCoreHeaderSize ? BitmapCoreHeaderSize : BitmapInfoHeaderSize;
            if (HeaderSize != BitmapCoreHeaderSize && HeaderSize < BitmapInfoHeaderSize)
                return false;

            if (!Instance.IsRegionMapped(Address, (ulong)ReadSize))
                return false;

            Span<byte> Header = Instance.WinHelper.Shared.GetSpan((ulong)ReadSize);
            if (!Instance.ReadMemory(Address, Header, (uint)ReadSize))
                return false;

            if (ReadSize == BitmapCoreHeaderSize)
            {
                Width = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x04, 2));
                Height = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x06, 2));
                Planes = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x08, 2));
                BitsPerPixel = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0A, 2));
                return true;
            }

            Width = BinaryPrimitives.ReadInt32LittleEndian(Header.Slice(0x04, 4));
            Height = BinaryPrimitives.ReadInt32LittleEndian(Header.Slice(0x08, 4));
            Planes = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0C, 2));
            BitsPerPixel = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0E, 2));
            Compression = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x10, 4));
            return true;
        }
    }
}
