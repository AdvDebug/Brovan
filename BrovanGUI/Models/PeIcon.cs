using System.Buffers.Binary;
using Avalonia;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Microsoft.Win32.SafeHandles;

namespace BrovanGUI.Models
{
    public static class PeIcon
    {
        private const int RtIcon = 3;
        private const int RtGroupIcon = 14;
        private const int MaxResourceSection = 32 * 1024 * 1024;

        public static Bitmap? Load(string Path)
        {
            try
            {
                using SafeFileHandle Handle = File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                return Extract(Handle);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static Bitmap? Extract(SafeFileHandle Handle)
        {
            Span<byte> Dos = stackalloc byte[0x40];
            if (RandomAccess.Read(Handle, Dos, 0) != Dos.Length || Dos[0] != 'M' || Dos[1] != 'Z')
                return null;

            int PeOffset = BinaryPrimitives.ReadInt32LittleEndian(Dos.Slice(0x3C));
            if (PeOffset <= 0)
                return null;

            Span<byte> Coff = stackalloc byte[24];
            if (RandomAccess.Read(Handle, Coff, PeOffset) != Coff.Length || Coff[0] != 'P' || Coff[1] != 'E')
                return null;

            int SectionCount = BinaryPrimitives.ReadUInt16LittleEndian(Coff.Slice(6));
            int OptionalSize = BinaryPrimitives.ReadUInt16LittleEndian(Coff.Slice(20));
            if (SectionCount == 0 || SectionCount > 96 || OptionalSize < 0x70)
                return null;

            byte[] Headers = new byte[OptionalSize + SectionCount * 40];
            if (RandomAccess.Read(Handle, Headers, PeOffset + 24) != Headers.Length)
                return null;

            ushort Magic = BinaryPrimitives.ReadUInt16LittleEndian(Headers);
            int DirectoryOffset = (Magic == 0x20B ? 0x70 : 0x60) + 2 * 8;
            if (DirectoryOffset + 8 > OptionalSize)
                return null;

            uint ResourceRva = BinaryPrimitives.ReadUInt32LittleEndian(Headers.AsSpan(DirectoryOffset));
            if (ResourceRva == 0)
                return null;

            uint SectionVa = 0;
            uint SectionRaw = 0;
            uint SectionSize = 0;
            for (int i = 0; i < SectionCount; i++)
            {
                ReadOnlySpan<byte> Entry = Headers.AsSpan(OptionalSize + i * 40, 40);
                uint VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8));
                uint VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(12));
                uint RawSize = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(16));
                uint RawPointer = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(20));
                if (ResourceRva >= VirtualAddress && ResourceRva < VirtualAddress + Math.Max(VirtualSize, RawSize))
                {
                    SectionVa = VirtualAddress;
                    SectionRaw = RawPointer;
                    SectionSize = RawSize;
                    break;
                }
            }

            if (SectionSize == 0 || SectionSize > MaxResourceSection)
                return null;

            byte[] Section = new byte[SectionSize];
            int Got = RandomAccess.Read(Handle, Section, SectionRaw);
            if (Got <= 0)
                return null;

            return Extract(Section.AsSpan(0, Got), SectionVa, (int)(ResourceRva - SectionVa));
        }

        // Offsets are relative to the resource section. Icon data in another section is not found.
        private static Bitmap? Extract(ReadOnlySpan<byte> Section, uint SectionVa, int Root)
        {
            int GroupDirectory = FindChild(Section, Root, Root, RtGroupIcon);
            int GroupLanguages = GroupDirectory < 0 ? -1 : FirstChild(Section, Root, GroupDirectory);
            int GroupData = GroupLanguages < 0 ? -1 : FirstChild(Section, Root, GroupLanguages);
            if (GroupData < 0 || !ReadData(Section, SectionVa, GroupData, out ReadOnlySpan<byte> Group) || Group.Length < 6)
                return null;

            int Count = BinaryPrimitives.ReadUInt16LittleEndian(Group.Slice(4));
            int BestScore = -1;
            int BestId = 0;
            for (int i = 0; i < Count; i++)
            {
                int Entry = 6 + i * 14;
                if (Entry + 14 > Group.Length)
                    break;

                int Width = Group[Entry] == 0 ? 256 : Group[Entry];
                int Bits = BinaryPrimitives.ReadUInt16LittleEndian(Group.Slice(Entry + 6));
                int Score = Width * 64 + Bits;
                if (Score > BestScore)
                {
                    BestScore = Score;
                    BestId = BinaryPrimitives.ReadUInt16LittleEndian(Group.Slice(Entry + 12));
                }
            }

            if (BestScore < 0)
                return null;

            int IconDirectory = FindChild(Section, Root, Root, RtIcon);
            int IconEntry = IconDirectory < 0 ? -1 : FindChild(Section, Root, IconDirectory, BestId);
            int IconLanguages = IconEntry < 0 ? -1 : FirstChild(Section, Root, IconEntry);
            if (IconLanguages < 0 || !ReadData(Section, SectionVa, IconLanguages, out ReadOnlySpan<byte> Icon))
                return null;

            if (Icon.Length > 8 && Icon[0] == 0x89 && Icon[1] == 'P' && Icon[2] == 'N' && Icon[3] == 'G')
                return new Bitmap(new MemoryStream(Icon.ToArray()));

            return FromDib(Icon);
        }

        private static int FindChild(ReadOnlySpan<byte> Section, int Root, int Directory, int Id)
        {
            if (Directory < 0 || Directory + 16 > Section.Length)
                return -1;

            int Named = BinaryPrimitives.ReadUInt16LittleEndian(Section.Slice(Directory + 12));
            int Numbered = BinaryPrimitives.ReadUInt16LittleEndian(Section.Slice(Directory + 14));
            for (int i = 0; i < Named + Numbered; i++)
            {
                int Entry = Directory + 16 + i * 8;
                if (Entry + 8 > Section.Length)
                    return -1;

                uint Name = BinaryPrimitives.ReadUInt32LittleEndian(Section.Slice(Entry));
                uint Target = BinaryPrimitives.ReadUInt32LittleEndian(Section.Slice(Entry + 4));
                if ((Name & 0x80000000) == 0 && Name == (uint)Id)
                    return Root + (int)(Target & 0x7FFFFFFF);
            }

            return -1;
        }

        private static int FirstChild(ReadOnlySpan<byte> Section, int Root, int Directory)
        {
            if (Directory < 0 || Directory + 24 > Section.Length)
                return -1;

            int Named = BinaryPrimitives.ReadUInt16LittleEndian(Section.Slice(Directory + 12));
            int Numbered = BinaryPrimitives.ReadUInt16LittleEndian(Section.Slice(Directory + 14));
            if (Named + Numbered == 0)
                return -1;

            uint Target = BinaryPrimitives.ReadUInt32LittleEndian(Section.Slice(Directory + 16 + 4));
            return Root + (int)(Target & 0x7FFFFFFF);
        }

        private static bool ReadData(ReadOnlySpan<byte> Section, uint SectionVa, int DataEntry, out ReadOnlySpan<byte> Data)
        {
            Data = default;
            if (DataEntry < 0 || DataEntry + 16 > Section.Length)
                return false;

            uint Rva = BinaryPrimitives.ReadUInt32LittleEndian(Section.Slice(DataEntry));
            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Section.Slice(DataEntry + 4));
            if (Rva < SectionVa)
                return false;

            long Offset = Rva - SectionVa;
            if (Offset + Size > Section.Length)
                return false;

            Data = Section.Slice((int)Offset, (int)Size);
            return true;
        }

        private static Bitmap? FromDib(ReadOnlySpan<byte> Dib)
        {
            if (Dib.Length < 40)
                return null;

            int HeaderSize = BinaryPrimitives.ReadInt32LittleEndian(Dib);
            int Width = BinaryPrimitives.ReadInt32LittleEndian(Dib.Slice(4));
            int Height = BinaryPrimitives.ReadInt32LittleEndian(Dib.Slice(8)) / 2;
            int Bits = BinaryPrimitives.ReadUInt16LittleEndian(Dib.Slice(14));
            int Compression = BinaryPrimitives.ReadInt32LittleEndian(Dib.Slice(16));
            if (HeaderSize < 40 || Width <= 0 || Height <= 0 || Width > 1024 || Height > 1024 || Compression != 0)
                return null;

            if (Bits != 32 && Bits != 24)
                return null;

            int BytesPerPixel = Bits / 8;
            int ColorStride = (Width * BytesPerPixel + 3) & ~3;
            int MaskStride = ((Width + 31) / 32) * 4;
            int ColorStart = HeaderSize;
            int MaskStart = ColorStart + ColorStride * Height;
            if (MaskStart > Dib.Length)
                return null;

            bool HasMask = MaskStart + MaskStride * Height <= Dib.Length;
            byte[] Pixels = new byte[Width * Height * 4];
            bool AnyAlpha = false;

            for (int y = 0; y < Height; y++)
            {
                int SourceRow = ColorStart + (Height - 1 - y) * ColorStride;
                int MaskRow = MaskStart + (Height - 1 - y) * MaskStride;
                for (int x = 0; x < Width; x++)
                {
                    int Source = SourceRow + x * BytesPerPixel;
                    int Target = (y * Width + x) * 4;
                    Pixels[Target] = Dib[Source];
                    Pixels[Target + 1] = Dib[Source + 1];
                    Pixels[Target + 2] = Dib[Source + 2];

                    byte Alpha = Bits == 32 ? Dib[Source + 3] : (byte)255;
                    if (HasMask && (Dib[MaskRow + x / 8] & (0x80 >> (x % 8))) != 0)
                        Alpha = 0;

                    Pixels[Target + 3] = Alpha;
                    if (Alpha != 0)
                        AnyAlpha = true;
                }
            }

            if (!AnyAlpha)
                return null;

            WriteableBitmap Bitmap = new WriteableBitmap(new PixelSize(Width, Height), new Vector(96, 96), PixelFormat.Bgra8888, AlphaFormat.Unpremul);
            using (ILockedFramebuffer Buffer = Bitmap.Lock())
            {
                for (int y = 0; y < Height; y++)
                    System.Runtime.InteropServices.Marshal.Copy(Pixels, y * Width * 4, Buffer.Address + y * Buffer.RowBytes, Width * 4);
            }

            return Bitmap;
        }
    }
}
