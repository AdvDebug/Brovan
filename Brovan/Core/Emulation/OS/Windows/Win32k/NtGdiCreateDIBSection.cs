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
        private const AccessMask SectionMapAccess = AccessMask.SectionMapRead | AccessMask.SectionMapWrite;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SectionHandle = Instance.WinHelper.GetArg(1);
            uint Offset = (uint)Instance.WinHelper.GetArg(2);
            ulong HeaderAddress = Instance.WinHelper.GetArg(3);
            ulong BitsPointerOut = Instance.WinHelper.GetArg(8);

            if (!TryReadHeader(Instance, HeaderAddress, out int Width, out int Height, out ushort Planes, out ushort BitsPerPixel, out uint Compression)
                || Planes != 1
                || (Compression != BI_RGB && Compression != BI_BITFIELDS))
            {
                return Fail(Instance);
            }

            bool TopDown = Height < 0;
            int AbsoluteHeight = TopDown ? -Height : Height;

            ulong Handle = SectionHandle != 0
                ? CreateOverSection(Instance, Width, AbsoluteHeight, BitsPerPixel, TopDown, SectionHandle, Offset)
                : Win32kHelper.CreateBitmap(Instance, Width, AbsoluteHeight, Planes, BitsPerPixel, true, TopDown);
            if (Handle == 0 || !Win32kHelper.TryGetBitmap(Instance, Handle, out Win32kBitmap Bitmap))
                return Fail(Instance);

            if (BitsPointerOut == 0 || !Instance.WinHelper.WritePointer(BitsPointerOut, Bitmap.BitsAddress))
            {
                Win32kHelper.RemoveBitmap(Instance, Handle);
                Instance.WinHelper.FreeGdiHandle(Handle);
                return Fail(Instance);
            }

            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong CreateOverSection(BinaryEmulator Instance, int Width, int Height, ushort BitsPerPixel, bool TopDown, ulong SectionHandle, uint Offset)
        {
            if (!Win32kHelper.TryGetBitmapLayout(Width, Height, 1, BitsPerPixel, true, out int Stride, out uint BitsSize))
                return 0;

            if (!Instance.WinHelper.HandleManager.TryGetHandle(SectionHandle, out HandleEntry Entry) || Entry.Object is not WinSection Section)
                return 0;

            if ((NtMapViewOfSection.MapSectionAccess(Entry.Permissions) & SectionMapAccess) != SectionMapAccess)
                return 0;

            if (Section.IsImage)
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage("[!] NtGdiCreateDIBSection: a DIB over an image section is not implemented.", LogFlags.Issues);
                return 0;
            }

            if (NtMapViewOfSection.CheckDataViewProtection(Section.Protection, WinSysHelper.PAGE_READWRITE) != NTSTATUS.STATUS_SUCCESS)
                return 0;

            // NT maps the view from the 64 KB boundary below the offset, just long enough for the bits.
            ulong Skew = Offset % WinSysHelper.AllocationGranularity;
            ulong ViewOffset = Offset - Skew;
            ulong RequestedSize = BitsSize + Skew;
            if (ViewOffset >= Section.Size || RequestedSize > Instance.AlignToPageSize(Section.Size) - ViewOffset)
                return 0;

            NTSTATUS Status = NtMapViewOfSection.MapDataView(Instance, Section, ViewOffset, Instance.AlignToPageSize(RequestedSize), 0,
                WinSysHelper.PAGE_READWRITE, out ulong ViewBase);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return 0;

            ulong Handle = Win32kHelper.AddBitmap(Instance, new Win32kBitmap
            {
                Width = Width,
                Height = Height,
                Planes = 1,
                BitsPerPixel = BitsPerPixel,
                Stride = Stride,
                BitsAddress = ViewBase + Skew,
                BitsSize = BitsSize,
                DibSection = true,
                TopDown = TopDown,
                ViewBase = ViewBase,
                SectionHandle = SectionHandle,
                SectionOffset = Offset,
            });

            if (Handle == 0)
                Instance.WinHelper.UnmapViewOfSection(ViewBase);

            return Handle;
        }

        private static NTSTATUS Fail(BinaryEmulator Instance)
        {
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
