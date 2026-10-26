using System.Buffers.Binary;
using System.Text;
using Brovan.Core;
using Brovan.WinFacts.Sources;

namespace Brovan.WinFacts.Readers
{
    internal readonly record struct PeSection(string Name, uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize, uint Characteristics)
    {
        private const uint Writable = 0x80000000;

        internal bool IsWritable => (Characteristics & Writable) != 0;
    }

    internal sealed class PeImage
    {
        private const uint PeSignature = 0x00004550;
        private const ushort Magic32 = 0x10B;
        private const ushort Magic64 = 0x20B;
        private const uint MaxHeaderOffset = 0x10000;
        private const int DebugDirectoryIndex = 6;
        private const uint DebugTypeCodeView = 2;
        private const uint CodeViewRsds = 0x53445352;
        private const int NtHeadersOffsetField = 0x3C;
        private const int SizeOfHeadersOffset = 0x3C;

        private readonly IByteSource Source;

        internal bool Is64 { get; }
        internal ulong ImageBase { get; }
        internal uint SizeOfImage { get; }
        internal IReadOnlyList<PeSection> Sections { get; }
        private readonly uint SizeOfHeaders;
        internal string PdbName { get; private set; }
        internal Guid PdbGuid { get; private set; }
        internal uint PdbAge { get; private set; }

        private readonly (uint Rva, uint Size)[] Directories;

        private PeImage(IByteSource Source, bool Is64, ulong ImageBase, uint SizeOfImage, uint SizeOfHeaders, List<PeSection> Sections, (uint, uint)[] Directories)
        {
            this.Source = Source;
            this.Is64 = Is64;
            this.ImageBase = ImageBase;
            this.SizeOfImage = SizeOfImage;
            this.SizeOfHeaders = SizeOfHeaders;
            this.Sections = Sections;
            this.Directories = Directories;
        }

        internal static PeImage Open(IByteSource Source)
        {
            Span<byte> Header = stackalloc byte[0x40];
            if (!Source.TryRead(0, Header) || Header[0] != 'M' || Header[1] != 'Z')
                throw new InvalidDataException("not a PE image");

            uint NtHeaders = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(NtHeadersOffsetField));
            if (NtHeaders > MaxHeaderOffset)
                throw new InvalidDataException("bad e_lfanew");

            byte[] Nt = new byte[0x108];
            if (!Source.TryRead(NtHeaders, Nt) || BinaryPrimitives.ReadUInt32LittleEndian(Nt) != PeSignature)
                throw new InvalidDataException("no PE signature");

            ushort SectionCount = BinaryPrimitives.ReadUInt16LittleEndian(Nt.AsSpan(6));
            ushort OptionalSize = BinaryPrimitives.ReadUInt16LittleEndian(Nt.AsSpan(20));
            ReadOnlySpan<byte> Optional = Nt.AsSpan(0x18);
            ushort Magic = BinaryPrimitives.ReadUInt16LittleEndian(Optional);
            if (Magic is not (Magic32 or Magic64))
                throw new InvalidDataException("unknown optional header");

            bool Is64 = Magic == Magic64;
            ulong ImageBase = Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(Optional.Slice(0x18)) : BinaryPrimitives.ReadUInt32LittleEndian(Optional.Slice(0x1C));
            uint SizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(Optional.Slice(0x38));
            uint SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(Optional.Slice(SizeOfHeadersOffset));
            int DirectoryBase = Is64 ? 0x70 : 0x60;
            uint DirectoryCount = Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(Optional.Slice(DirectoryBase - 4)), 16u);
            (uint, uint)[] Directories = new (uint, uint)[16];
            for (int i = 0; i < DirectoryCount; i++)
            {
                ReadOnlySpan<byte> Entry = Optional.Slice(DirectoryBase + i * 8);
                Directories[i] = (BinaryPrimitives.ReadUInt32LittleEndian(Entry), BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4)));
            }

            byte[] Table = new byte[SectionCount * 40];
            if (!Source.TryRead(NtHeaders + 0x18 + OptionalSize, Table))
                throw new InvalidDataException("truncated section table");

            List<PeSection> Sections = new(SectionCount);
            for (int i = 0; i < SectionCount; i++)
            {
                ReadOnlySpan<byte> Entry = Table.AsSpan(i * 40, 40);
                string Name = Encoding.ASCII.GetString(Entry.Slice(0, 8)).TrimEnd('\0');
                Sections.Add(new PeSection(Name, BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(12)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8)), BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(20)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(16)), BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(36))));
            }

            PeImage Image = new(Source, Is64, ImageBase, SizeOfImage, SizeOfHeaders, Sections, Directories);
            Image.ReadCodeView();
            return Image;
        }

        internal bool TryReadRva(uint Rva, Span<byte> Destination)
        {
            if (Rva < SizeOfHeaders)
                return (ulong)Rva + (ulong)Destination.Length <= SizeOfHeaders && Source.TryRead(Rva, Destination);

            foreach (PeSection Section in Sections)
            {
                if (Rva < Section.VirtualAddress || Rva >= Section.VirtualAddress + Math.Max(Section.VirtualSize, Section.RawSize))
                    continue;

                ulong Delta = Rva - Section.VirtualAddress;
                if (Delta + (ulong)Destination.Length > Section.RawSize)
                {
                    // Bytes past the raw data are zero in the loaded image.
                    if (Delta >= Section.RawSize)
                    {
                        Destination.Clear();
                        return Delta + (ulong)Destination.Length <= Math.Max(Section.VirtualSize, Section.RawSize);
                    }

                    int Raw = (int)(Section.RawSize - Delta);
                    Destination.Slice(Raw).Clear();
                    return Source.TryRead(Section.RawOffset + (long)Delta, Destination.Slice(0, Raw));
                }

                return Source.TryRead(Section.RawOffset + (long)Delta, Destination);
            }

            return false;
        }

        internal byte[] ReadRva(uint Rva, int Count)
        {
            byte[] Bytes = new byte[Count];
            ReadRva(Rva, Bytes);
            return Bytes;
        }

        private void ReadRva(uint Rva, Span<byte> Destination)
        {
            if (!TryReadRva(Rva, Destination))
                throw new InvalidDataException($"RVA 0x{Rva:X} (+{Destination.Length}) is outside the image");
        }

        internal (uint Rva, uint Size) Directory(int Index) => Directories[Index];

        internal uint ReadUInt32(uint Rva)
        {
            Span<byte> Bytes = stackalloc byte[sizeof(uint)];
            ReadRva(Rva, Bytes);
            return BinaryPrimitives.ReadUInt32LittleEndian(Bytes);
        }

        internal ulong ReadUInt64(uint Rva)
        {
            Span<byte> Bytes = stackalloc byte[sizeof(ulong)];
            ReadRva(Rva, Bytes);
            return BinaryPrimitives.ReadUInt64LittleEndian(Bytes);
        }

        internal byte[] ReadSection(PeSection Section)
        {
            byte[] Bytes = new byte[Math.Max(Section.VirtualSize, Section.RawSize)];
            if (Section.RawSize != 0 && !Source.TryRead(Section.RawOffset, Bytes.AsSpan(0, (int)Math.Min(Section.RawSize, (uint)Bytes.Length))))
                throw new InvalidDataException($"section {Section.Name} is truncated");

            return Bytes;
        }

        // Read by Brovan's own ImageResources, so the tool keys a version exactly as Brovan does at run time.
        internal (ushort Build, ushort Revision)? FileVersion()
            => ImageResources.TryReadFileVersion(new Reader(this), out ushort Build, out ushort Revision) ? (Build, Revision) : null;

        private readonly struct Reader : IImageReader
        {
            private readonly PeImage Image;

            internal Reader(PeImage Image)
            {
                this.Image = Image;
            }

            public bool TryRead(uint Rva, Span<byte> Destination) => Image.TryReadRva(Rva, Destination);
        }

        private void ReadCodeView()
        {
            (uint Rva, uint Size) = Directories[DebugDirectoryIndex];
            for (uint Entry = 0; Entry + 28 <= Size; Entry += 28)
            {
                byte[] Debug = ReadRva(Rva + Entry, 28);
                if (BinaryPrimitives.ReadUInt32LittleEndian(Debug.AsSpan(12)) != DebugTypeCodeView)
                    continue;

                uint DataSize = BinaryPrimitives.ReadUInt32LittleEndian(Debug.AsSpan(16));
                uint DataRva = BinaryPrimitives.ReadUInt32LittleEndian(Debug.AsSpan(20));
                if (DataSize < 24 || DataSize > 0x400)
                    continue;

                byte[] Record = ReadRva(DataRva, (int)DataSize);
                if (BinaryPrimitives.ReadUInt32LittleEndian(Record) != CodeViewRsds)
                    continue;

                PdbGuid = new Guid(Record.AsSpan(4, 16));
                PdbAge = BinaryPrimitives.ReadUInt32LittleEndian(Record.AsSpan(20));
                int End = Array.IndexOf(Record, (byte)0, 24);
                PdbName = Path.GetFileName(Encoding.UTF8.GetString(Record, 24, (End < 0 ? Record.Length : End) - 24));
                return;
            }
        }
    }
}
