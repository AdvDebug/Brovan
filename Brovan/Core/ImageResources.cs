using System;
using System.Buffers.Binary;
using System.IO;

namespace Brovan.Core
{
    internal interface IImageReader
    {
        bool TryRead(uint Rva, Span<byte> Destination);
    }

    // Reads only the headers and the section table, so a large image is never parsed or loaded.
    internal readonly struct ImageStream : IImageReader
    {
        internal const int NtHeadersOffsetField = 0x3C;
        internal const int OptionalHeaderOffset = 0x18;

        private const int HeaderBytes = 0x1000;
        private const int SectionCountOffset = 0x06;
        private const int OptionalHeaderSizeOffset = 0x14;
        private const int SizeOfHeadersOffset = 0x3C;
        private const int SectionHeaderSize = 40;
        private const int MaxSections = 96;

        private readonly record struct Section(uint VirtualAddress, uint VirtualSize, uint RawSize, uint RawOffset);

        private readonly Stream Stream;
        private readonly byte[] Headers;
        private readonly uint SizeOfHeaders;
        private readonly Section[] Sections;

        private ImageStream(Stream Stream, byte[] Headers, uint SizeOfHeaders, Section[] Sections)
        {
            this.Stream = Stream;
            this.Headers = Headers;
            this.SizeOfHeaders = SizeOfHeaders;
            this.Sections = Sections;
        }

        internal static bool TryOpen(Stream Stream, out ImageStream Image)
        {
            Image = default;
            byte[] Headers = new byte[(int)Math.Min(HeaderBytes, Stream.Length)];
            Stream.Position = 0;
            Stream.ReadExactly(Headers);
            if (Headers.Length < NtHeadersOffsetField + 4)
                return false;

            uint NtHeaders = BinaryPrimitives.ReadUInt32LittleEndian(Headers.AsSpan(NtHeadersOffsetField));
            if (NtHeaders > Headers.Length - OptionalHeaderOffset - SizeOfHeadersOffset - 4)
                return false;

            int Count = BinaryPrimitives.ReadUInt16LittleEndian(Headers.AsSpan((int)NtHeaders + SectionCountOffset));
            int OptionalSize = BinaryPrimitives.ReadUInt16LittleEndian(Headers.AsSpan((int)NtHeaders + OptionalHeaderSizeOffset));
            int Table = (int)NtHeaders + OptionalHeaderOffset + OptionalSize;
            if (Count > MaxSections || Table + Count * SectionHeaderSize > Headers.Length)
                return false;

            Section[] Sections = new Section[Count];
            for (int i = 0; i < Count; i++)
            {
                ReadOnlySpan<byte> Entry = Headers.AsSpan(Table + i * SectionHeaderSize, SectionHeaderSize);
                Sections[i] = new Section(VirtualAddress: BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(12)),
                    VirtualSize: BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(8)), RawSize: BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(16)),
                    RawOffset: BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(20)));
            }

            uint SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(Headers.AsSpan((int)NtHeaders + OptionalHeaderOffset + SizeOfHeadersOffset));
            Image = new ImageStream(Stream, Headers, SizeOfHeaders, Sections);
            return true;
        }

        public bool TryRead(uint Rva, Span<byte> Destination)
        {
            if (Rva < SizeOfHeaders)
            {
                if (Rva > Headers.Length || Destination.Length > Headers.Length - Rva)
                    return false;

                Headers.AsSpan((int)Rva, Destination.Length).CopyTo(Destination);
                return true;
            }

            foreach (Section Section in Sections)
            {
                if (Rva < Section.VirtualAddress || Rva - Section.VirtualAddress >= Math.Max(Section.VirtualSize, Section.RawSize))
                    continue;

                uint Delta = Rva - Section.VirtualAddress;
                if (Delta > Section.RawSize || (ulong)Destination.Length > Section.RawSize - Delta)
                    return false;

                long Offset = (long)Section.RawOffset + Delta;
                if (Offset > Stream.Length - Destination.Length)
                    return false;

                Stream.Position = Offset;
                Stream.ReadExactly(Destination);
                return true;
            }

            return false;
        }
    }

    internal static class ImageResources
    {
        internal const uint TypeVersion = 16;
        internal const uint TypeManifest = 24;

        private const uint MaxHeaderOffset = 0x10000;
        private const uint PeSignature = 0x00004550;
        private const ushort OptionalHeaderMagic32 = 0x10B;
        private const ushort OptionalHeaderMagic64 = 0x20B;
        private const int DataDirectoryCountOffset32 = 0x5C;
        private const int DataDirectoryCountOffset64 = 0x6C;
        private const int DataDirectorySize = 8;
        private const uint ResourceDataDirectoryIndex = 2;
        private const int ResourceDirectoryHeaderSize = 0x10;
        private const int ResourceDirectoryEntrySize = 8;
        private const int ResourceDataEntrySize = 0x10;
        private const int MaxResourceDirectoryEntries = 0x1000;

        // VS_VERSIONINFO puts VS_FIXEDFILEINFO after its 6-byte header and the aligned key L"VS_VERSION_INFO".
        private const uint FixedFileInfoOffset = 0x28;
        private const uint FixedFileInfoSize = 0x34;
        private const uint FixedFileInfoSignature = 0xFEEF04BD;
        private const int FileVersionLowOffset = 0x0C;

        // This takes the first language of the resource.
        internal static bool TryFindResource<TImage>(TImage Image, uint Type, uint Id, out uint DataRva, out uint DataSize) where TImage : struct, IImageReader
        {
            DataRva = 0;
            DataSize = 0;
            if (!TryGetResourceDirectory(Image, out uint Root))
                return false;

            if (!TryFindDirectoryEntry(Image, Root, Root, Type, out uint TypeDirectory, out bool IsDirectory) || !IsDirectory)
                return false;

            if (!TryFindDirectoryEntry(Image, Root, TypeDirectory, Id, out uint NameDirectory, out IsDirectory) || !IsDirectory)
                return false;

            if (!TryFindDirectoryEntry(Image, Root, NameDirectory, uint.MaxValue, out uint DataEntry, out IsDirectory) || IsDirectory)
                return false;

            Span<byte> Entry = stackalloc byte[ResourceDataEntrySize];
            if (!Image.TryRead(DataEntry, Entry))
                return false;

            DataRva = BinaryPrimitives.ReadUInt32LittleEndian(Entry);
            DataSize = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4));
            return DataRva != 0 && DataSize != 0;
        }

        internal static bool TryReadFileVersion<TImage>(TImage Image, out ushort Build, out ushort Revision) where TImage : struct, IImageReader
        {
            Build = 0;
            Revision = 0;
            if (!TryFindResource(Image, TypeVersion, 1, out uint DataRva, out uint DataSize) || DataSize < FixedFileInfoOffset + FixedFileInfoSize)
                return false;

            Span<byte> Info = stackalloc byte[(int)FixedFileInfoSize];
            if (!Image.TryRead(DataRva + FixedFileInfoOffset, Info) || BinaryPrimitives.ReadUInt32LittleEndian(Info) != FixedFileInfoSignature)
                return false;

            uint VersionLow = BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(FileVersionLowOffset));
            Build = (ushort)(VersionLow >> 16);
            Revision = (ushort)VersionLow;
            return true;
        }

        internal static bool TryReadFileVersion(string HostPath, out ushort Build, out ushort Revision)
        {
            Build = 0;
            Revision = 0;
            try
            {
                using FileStream Stream = new(HostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 0x1000, FileOptions.RandomAccess);
                return ImageStream.TryOpen(Stream, out ImageStream Image) && TryReadFileVersion(Image, out Build, out Revision);
            }
            catch (Exception Error) when (Error is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }

        private static bool TryGetResourceDirectory<TImage>(TImage Image, out uint Root) where TImage : struct, IImageReader
        {
            Root = 0;
            Span<byte> Field = stackalloc byte[4];
            if (!Image.TryRead(ImageStream.NtHeadersOffsetField, Field))
                return false;

            uint NtHeaders = BinaryPrimitives.ReadUInt32LittleEndian(Field);
            if (NtHeaders > MaxHeaderOffset || !Image.TryRead(NtHeaders, Field) || BinaryPrimitives.ReadUInt32LittleEndian(Field) != PeSignature)
                return false;

            uint Optional = NtHeaders + ImageStream.OptionalHeaderOffset;
            if (!Image.TryRead(Optional, Field.Slice(0, 2)))
                return false;

            int CountOffset = BinaryPrimitives.ReadUInt16LittleEndian(Field) switch
            {
                OptionalHeaderMagic32 => DataDirectoryCountOffset32,
                OptionalHeaderMagic64 => DataDirectoryCountOffset64,
                _ => -1
            };
            if (CountOffset < 0 || !Image.TryRead(Optional + (uint)CountOffset, Field) || BinaryPrimitives.ReadUInt32LittleEndian(Field) <= ResourceDataDirectoryIndex)
                return false;

            uint Directory = Optional + (uint)CountOffset + 4 + ResourceDataDirectoryIndex * DataDirectorySize;
            if (!Image.TryRead(Directory, Field))
                return false;

            Root = BinaryPrimitives.ReadUInt32LittleEndian(Field);
            return Root != 0;
        }

        private static bool TryFindDirectoryEntry<TImage>(TImage Image, uint Root, uint Directory, uint Id, out uint Target, out bool IsDirectory) where TImage : struct, IImageReader
        {
            Target = 0;
            IsDirectory = false;

            Span<byte> Header = stackalloc byte[ResourceDirectoryHeaderSize];
            if (!Image.TryRead(Directory, Header))
                return false;

            int NamedEntries = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0C));
            int IdEntries = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x0E));
            int TotalEntries = NamedEntries + IdEntries;
            if (TotalEntries <= 0 || TotalEntries > MaxResourceDirectoryEntries)
                return false;

            Span<byte> Entry = stackalloc byte[ResourceDirectoryEntrySize];
            uint EntryBase = Directory + ResourceDirectoryHeaderSize;
            for (int i = NamedEntries; i < TotalEntries; i++)
            {
                if (!Image.TryRead(EntryBase + (uint)(i * ResourceDirectoryEntrySize), Entry))
                    return false;

                uint EntryId = BinaryPrimitives.ReadUInt32LittleEndian(Entry);
                if (Id != uint.MaxValue && EntryId != Id)
                    continue;

                uint OffsetToData = BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4));
                IsDirectory = (OffsetToData & 0x80000000u) != 0;
                Target = Root + (OffsetToData & 0x7FFFFFFFu);
                return true;
            }

            return false;
        }
    }
}
