using System.Buffers.Binary;
using System.Text;
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
        private const int RtVersion = 16;
        private const int VersionBlockHeader = 6;
        private const int StringFileInfoDepth = 1;
        private const int VersionStringDepth = 3;
        private const int PreferredSize = 48;
        private const int MaxIconSize = 1024;
        private const int MaxResourceData = 8 * 1024 * 1024;

        public static Bitmap? Load(string Path)
        {
            try
            {
                byte[]? Icon;
                using (SafeFileHandle Handle = File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    Icon = ReadIcon(Handle);

                string Resources = SystemResourcesFor(Path);
                if (Icon == null && File.Exists(Resources))
                {
                    using SafeFileHandle Handle = File.OpenHandle(Resources, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    Icon = ReadIcon(Handle);
                }

                if (Icon == null)
                    return null;

                if (Icon.Length > 8 && Icon[0] == 0x89 && Icon[1] == 'P' && Icon[2] == 'N' && Icon[3] == 'G')
                    return FromPng(Icon);

                return FromDib(Icon);
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Windows 11 keeps the icons of its own programs in SystemResources\<file>.mun, a resource-only image.
        private static string SystemResourcesFor(string Program)
        {
            string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (Windows.Length == 0 || !Program.StartsWith(Windows, StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            return System.IO.Path.Combine(Windows, "SystemResources", System.IO.Path.GetFileName(Program) + ".mun");
        }

        public static string?[] VersionNames(string Path)
        {
            string?[] Names = new string?[2];
            try
            {
                using SafeFileHandle Handle = File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (!TryOpenResources(Handle, out ResourceSection Section))
                    return Names;

                byte[]? Data = Section.ReadData(Section.FirstChild(Section.FirstChild(Section.FindChild(Section.Root, RtVersion))));
                if (Data != null)
                    CollectNames(Data, 0, Data.Length, 0, Names);
            }
            catch (Exception)
            {
            }

            return Names;
        }

        // VS_VERSIONINFO, StringFileInfo, StringTable and String share one layout: length, value length, type,
        // a UTF-16 key, then the value and the children, each aligned to 4 bytes.
        private static void CollectNames(byte[] Data, int At, int End, int Depth, string?[] Names)
        {
            while (At + VersionBlockHeader <= End)
            {
                int BlockLength = BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan(At));
                if (BlockLength < VersionBlockHeader || At + BlockLength > End)
                    return;

                int BlockEnd = At + BlockLength;
                int KeyStart = At + VersionBlockHeader;
                int KeyEnd = Utf16End(Data, KeyStart, BlockEnd);
                string Key = Encoding.Unicode.GetString(Data, KeyStart, KeyEnd - KeyStart);
                bool Text = BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan(At + 4)) == 1;
                int ValueLength = BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan(At + 2)) * (Text ? 2 : 1);
                int Value = Math.Min(Align4(KeyEnd + 2), BlockEnd);
                int ValueEnd = Math.Min(Value + ValueLength, BlockEnd);

                if (Depth == VersionStringDepth)
                    StoreName(Key, Data, Value, ValueEnd, Names);
                else if (Depth != StringFileInfoDepth || Key == "StringFileInfo")
                    CollectNames(Data, Math.Min(Align4(ValueEnd), BlockEnd), BlockEnd, Depth + 1, Names);

                At = Align4(BlockEnd);
            }
        }

        private static void StoreName(string Key, byte[] Data, int From, int To, string?[] Names)
        {
            int Slot = Key == "FileDescription" ? 0 : Key == "ProductName" ? 1 : -1;
            if (Slot < 0 || Names[Slot] != null)
                return;

            string Value = Encoding.Unicode.GetString(Data, From, Utf16End(Data, From, To) - From).Trim();
            if (Value.Length != 0)
                Names[Slot] = Value;
        }

        private static int Utf16End(byte[] Data, int From, int To)
        {
            while (From + 2 <= To && BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan(From)) != 0)
                From += 2;

            return From;
        }

        private static int Align4(int At) => (At + 3) & ~3;

        private static byte[]? ReadIcon(SafeFileHandle Handle)
        {
            if (!TryOpenResources(Handle, out ResourceSection Section))
                return null;

            long GroupDirectory = Section.FindChild(Section.Root, RtGroupIcon);
            long GroupLanguages = Section.FirstChild(GroupDirectory);
            byte[]? Group = Section.ReadData(Section.FirstChild(GroupLanguages));
            if (Group == null || Group.Length < 6)
                return null;

            int Count = BinaryPrimitives.ReadUInt16LittleEndian(Group.AsSpan(4));
            int BestId = -1;
            (bool, bool, int, int) BestRank = default;
            for (int i = 0; i < Count; i++)
            {
                int Entry = 6 + i * 14;
                if (Entry + 14 > Group.Length)
                    break;

                int Size = Group[Entry] == 0 ? 256 : Group[Entry];
                int Bits = BinaryPrimitives.ReadUInt16LittleEndian(Group.AsSpan(Entry + 6));
                if (Bits == 0)
                    Bits = Group[Entry + 2] switch { 0 => 8, <= 2 => 1, <= 16 => 4, _ => 8 };

                (bool, bool, int, int) Rank = IconRank(Size, Bits);
                if (BestId < 0 || Rank.CompareTo(BestRank) > 0)
                {
                    BestId = BinaryPrimitives.ReadUInt16LittleEndian(Group.AsSpan(Entry + 12));
                    BestRank = Rank;
                }
            }

            if (BestId < 0)
                return null;

            long IconDirectory = Section.FindChild(Section.Root, RtIcon);
            long IconEntry = Section.FindChild(IconDirectory, BestId);
            return Section.ReadData(Section.FirstChild(IconEntry));
        }

        private static bool TryOpenResources(SafeFileHandle Handle, out ResourceSection Section)
        {
            Section = default;
            Span<byte> Dos = stackalloc byte[0x40];
            if (RandomAccess.Read(Handle, Dos, 0) != Dos.Length || Dos[0] != 'M' || Dos[1] != 'Z')
                return false;

            int PeOffset = BinaryPrimitives.ReadInt32LittleEndian(Dos.Slice(0x3C));
            if (PeOffset <= 0)
                return false;

            Span<byte> Coff = stackalloc byte[24];
            if (RandomAccess.Read(Handle, Coff, PeOffset) != Coff.Length || Coff[0] != 'P' || Coff[1] != 'E')
                return false;

            int SectionCount = BinaryPrimitives.ReadUInt16LittleEndian(Coff.Slice(6));
            int OptionalSize = BinaryPrimitives.ReadUInt16LittleEndian(Coff.Slice(20));
            if (SectionCount == 0 || SectionCount > 96 || OptionalSize < 0x70)
                return false;

            byte[] Headers = new byte[OptionalSize + SectionCount * 40];
            if (RandomAccess.Read(Handle, Headers, (long)PeOffset + 24) != Headers.Length)
                return false;

            ushort Magic = BinaryPrimitives.ReadUInt16LittleEndian(Headers);
            int DirectoryOffset = (Magic == 0x20B ? 0x70 : 0x60) + 2 * 8;
            if (DirectoryOffset + 8 > OptionalSize)
                return false;

            uint ResourceRva = BinaryPrimitives.ReadUInt32LittleEndian(Headers.AsSpan(DirectoryOffset));
            if (ResourceRva == 0)
                return false;

            for (int i = 0; i < SectionCount; i++)
            {
                ReadOnlySpan<byte> Entry = Headers.AsSpan(OptionalSize + i * 40, 40);
                uint VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8));
                uint VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(12));
                uint RawSize = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(16));
                uint RawPointer = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(20));
                if (ResourceRva >= VirtualAddress && ResourceRva < (ulong)VirtualAddress + Math.Max(VirtualSize, RawSize))
                {
                    if (RawSize == 0)
                        return false;

                    Section = new ResourceSection(Handle, RawPointer, RawSize, VirtualAddress, ResourceRva - VirtualAddress);
                    return true;
                }
            }

            return false;
        }

        // True colour first, then the smallest size that is still sharp at 200% scale, then depth.
        private static (bool, bool, int, int) IconRank(int Size, int Bits)
        {
            bool Large = Size >= PreferredSize;
            return (Bits >= 24, Large, Large ? -Size : Size, Bits);
        }

        private static Bitmap? FromPng(byte[] Png)
        {
            if (Png.Length < 24 || Png[12] != 'I' || Png[13] != 'H' || Png[14] != 'D' || Png[15] != 'R')
                return null;

            int Width = BinaryPrimitives.ReadInt32BigEndian(Png.AsSpan(16));
            int Height = BinaryPrimitives.ReadInt32BigEndian(Png.AsSpan(20));
            if (Width <= 0 || Height <= 0 || Width > MaxIconSize || Height > MaxIconSize)
                return null;

            return new Bitmap(new MemoryStream(Png, false));
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
            int ColorsUsed = BinaryPrimitives.ReadInt32LittleEndian(Dib.Slice(32));
            if (HeaderSize < 40 || HeaderSize > Dib.Length || Width <= 0 || Height <= 0 || Width > MaxIconSize || Height > MaxIconSize || Compression != 0)
                return null;

            if (Bits is not (1 or 4 or 8 or 24 or 32))
                return null;

            int PaletteSize = ColorsUsed > 0 ? Math.Min(ColorsUsed, 256) : Bits <= 8 ? 1 << Bits : 0;

            int PaletteStart = HeaderSize;
            int ColorStart = PaletteStart + PaletteSize * 4;
            int ColorStride = (Width * Bits + 31) / 32 * 4;
            int MaskStride = (Width + 31) / 32 * 4;
            int MaskStart = ColorStart + ColorStride * Height;
            if (MaskStart > Dib.Length)
                return null;

            // user32 draws a 32-bit icon from its alpha and ignores the mask, unless every alpha byte is zero.
            bool UseAlpha = Bits == 32 && HasAlpha(Dib.Slice(ColorStart, ColorStride * Height));
            bool HasMask = MaskStart + MaskStride * Height <= Dib.Length;
            byte[] Pixels = new byte[Width * Height * 4];
            bool AnyVisible = false;

            for (int y = 0; y < Height; y++)
            {
                int SourceRow = ColorStart + (Height - 1 - y) * ColorStride;
                int MaskRow = MaskStart + (Height - 1 - y) * MaskStride;
                for (int x = 0; x < Width; x++)
                {
                    int Source;
                    if (Bits <= 8)
                    {
                        int Bit = x * Bits;
                        int Index = (Dib[SourceRow + Bit / 8] >> (8 - Bits - Bit % 8)) & ((1 << Bits) - 1);
                        Source = PaletteStart + (Index < PaletteSize ? Index : 0) * 4;
                    }
                    else
                    {
                        Source = SourceRow + x * (Bits / 8);
                    }

                    int Target = (y * Width + x) * 4;
                    Pixels[Target] = Dib[Source];
                    Pixels[Target + 1] = Dib[Source + 1];
                    Pixels[Target + 2] = Dib[Source + 2];

                    byte Alpha = UseAlpha ? Dib[Source + 3] : (byte)255;
                    if (!UseAlpha && HasMask && (Dib[MaskRow + x / 8] & (0x80 >> (x % 8))) != 0)
                        Alpha = 0;

                    Pixels[Target + 3] = Alpha;
                    if (Alpha != 0)
                        AnyVisible = true;
                }
            }

            if (!AnyVisible)
                return null;

            WriteableBitmap Bitmap = new WriteableBitmap(new PixelSize(Width, Height), new Vector(96, 96), PixelFormat.Bgra8888, AlphaFormat.Unpremul);
            using (ILockedFramebuffer Buffer = Bitmap.Lock())
            {
                for (int y = 0; y < Height; y++)
                    System.Runtime.InteropServices.Marshal.Copy(Pixels, y * Width * 4, Buffer.Address + y * Buffer.RowBytes, Width * 4);
            }

            return Bitmap;
        }

        private static bool HasAlpha(ReadOnlySpan<byte> Pixels)
        {
            for (int i = 3; i < Pixels.Length; i += 4)
            {
                if (Pixels[i] != 0)
                    return true;
            }

            return false;
        }

        // Offsets are relative to the resource section. Icon data in another section is not found.
        private readonly struct ResourceSection
        {
            private const int EntryChunk = 512;

            private readonly SafeFileHandle Handle;
            private readonly long FileOffset;
            private readonly long Length;
            private readonly uint VirtualAddress;

            public ResourceSection(SafeFileHandle Handle, long FileOffset, long Length, uint VirtualAddress, long Root)
            {
                this.Handle = Handle;
                this.FileOffset = FileOffset;
                this.Length = Length;
                this.VirtualAddress = VirtualAddress;
                this.Root = Root;
            }

            public long Root { get; }

            public long FindChild(long Directory, int Id)
            {
                Span<byte> Header = stackalloc byte[16];
                if (!Read(Directory, Header))
                    return -1;

                int Count = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(12)) + BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(14));
                Span<byte> Entries = stackalloc byte[Math.Min(Count, EntryChunk) * 8];
                for (int Start = 0; Start < Count; Start += EntryChunk)
                {
                    Span<byte> Chunk = Entries.Slice(0, Math.Min(EntryChunk, Count - Start) * 8);
                    if (!Read(Directory + 16 + Start * 8L, Chunk))
                        return -1;

                    for (int Entry = 0; Entry < Chunk.Length; Entry += 8)
                    {
                        if (BinaryPrimitives.ReadUInt32LittleEndian(Chunk.Slice(Entry)) == (uint)Id)
                            return Root + (BinaryPrimitives.ReadUInt32LittleEndian(Chunk.Slice(Entry + 4)) & 0x7FFFFFFF);
                    }
                }

                return -1;
            }

            public long FirstChild(long Directory)
            {
                Span<byte> Header = stackalloc byte[24];
                if (!Read(Directory, Header))
                    return -1;

                int Named = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(12));
                int Numbered = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(14));
                if (Named + Numbered == 0)
                    return -1;

                return Root + (BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(20)) & 0x7FFFFFFF);
            }

            public byte[]? ReadData(long DataEntry)
            {
                Span<byte> Entry = stackalloc byte[16];
                if (!Read(DataEntry, Entry))
                    return null;

                uint Rva = BinaryPrimitives.ReadUInt32LittleEndian(Entry);
                uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4));
                long Offset = (long)Rva - VirtualAddress;
                if (Offset < 0 || Size > MaxResourceData || Offset > Length - Size)
                    return null;

                byte[] Data = new byte[Size];
                return Read(Offset, Data) ? Data : null;
            }

            private bool Read(long Offset, Span<byte> Buffer)
            {
                if (Offset < 0 || Offset > Length - Buffer.Length)
                    return false;

                return RandomAccess.Read(Handle, Buffer, FileOffset + Offset) == Buffer.Length;
            }
        }
    }
}
