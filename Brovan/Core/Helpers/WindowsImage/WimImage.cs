using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal struct WimDirectoryEntry
    {
        public string Name;
        public uint Attributes;
        public long SubdirectoryOffset;
        public Sha1Hash Hash;

        public readonly bool IsDirectory => (Attributes & 0x10) != 0;
        public readonly bool IsReparsePoint => (Attributes & 0x400) != 0;
    }

    /// <summary>
    /// Directory tree of one image inside a WIM. The metadata resource stays compressed on the backing image and is
    /// decoded chunk by chunk as the tree is walked.
    /// </summary>
    internal sealed class WimImage : IDisposable
    {
        private const int DentryFixedSize = 102;
        private const int StreamEntryFixedSize = 38;

        private readonly WimReader Reader;
        private readonly ImageDataSource Metadata;

        public long RootOffset { get; }

        public WimImage(WimReader Reader, ImageDataSource Metadata)
        {
            this.Reader = Reader;
            this.Metadata = Metadata;

            Span<byte> Security = stackalloc byte[8];
            Metadata.ReadExact(0, Security);

            long TotalLength = BinaryPrimitives.ReadUInt32LittleEndian(Security);
            if (TotalLength == 0)
                TotalLength = 8;

            long Start = (TotalLength + 7) & ~7L;
            long Cursor = Start;

            RootOffset = TryReadEntry(ref Cursor, out WimDirectoryEntry Root) && Root.IsDirectory && Root.Name.Length == 0
                ? Root.SubdirectoryOffset
                : Start;
        }

        public bool TryFindFile(string Path, out WimDirectoryEntry Entry)
        {
            Entry = default;

            string[] Parts = IsoReader.SplitPath(Path);
            if (Parts.Length == 0)
                return false;

            long Offset = RootOffset;

            for (int i = 0; i < Parts.Length - 1; i++)
            {
                if (!TryFindChild(Offset, Parts[i], out WimDirectoryEntry Directory) || !Directory.IsDirectory)
                    return false;

                Offset = Directory.SubdirectoryOffset;
            }

            return TryFindChild(Offset, Parts[Parts.Length - 1], out Entry);
        }

        private bool TryFindChild(long DirectoryOffset, string Name, out WimDirectoryEntry Entry)
        {
            Entry = default;

            if (DirectoryOffset == 0)
                return false;

            long Offset = DirectoryOffset;

            while (TryReadEntry(ref Offset, out WimDirectoryEntry Candidate))
            {
                if (string.Equals(Candidate.Name, Name, StringComparison.OrdinalIgnoreCase))
                {
                    Entry = Candidate;
                    return true;
                }
            }

            return false;
        }

        public void ListDirectory(long DirectoryOffset, List<WimDirectoryEntry> Into)
        {
            if (DirectoryOffset == 0)
                return;

            long Offset = DirectoryOffset;

            while (TryReadEntry(ref Offset, out WimDirectoryEntry Entry))
                Into.Add(Entry);
        }

        private bool TryReadEntry(ref long Offset, out WimDirectoryEntry Entry)
        {
            Entry = default;

            Span<byte> Fixed = stackalloc byte[DentryFixedSize];
            Metadata.ReadExact(Offset, Fixed.Slice(0, 8));

            long Length = (long)BinaryPrimitives.ReadUInt64LittleEndian(Fixed);
            if (Length == 0)
                return false;

            if (Length < DentryFixedSize || Length > (1 << 20))
                throw new InvalidDataException($"A directory entry at offset {Offset} declares a length of {Length}.");

            Metadata.ReadExact(Offset, Fixed);

            Entry.Attributes = BinaryPrimitives.ReadUInt32LittleEndian(Fixed.Slice(8));
            Entry.SubdirectoryOffset = (long)BinaryPrimitives.ReadUInt64LittleEndian(Fixed.Slice(16));
            Entry.Hash = new Sha1Hash(Fixed.Slice(64, 20));

            int ExtraStreams = BinaryPrimitives.ReadUInt16LittleEndian(Fixed.Slice(96));
            int NameLength = BinaryPrimitives.ReadUInt16LittleEndian(Fixed.Slice(100));

            if (NameLength > 0)
            {
                if (DentryFixedSize + NameLength > Length)
                    throw new InvalidDataException($"A directory entry at offset {Offset} declares a {NameLength} byte name that does not fit in {Length} bytes.");

                byte[] Buffer = ArrayPool<byte>.Shared.Rent(NameLength);

                try
                {
                    Span<byte> Raw = Buffer.AsSpan(0, NameLength);
                    Metadata.ReadExact(Offset + DentryFixedSize, Raw);
                    Entry.Name = Encoding.Unicode.GetString(Raw);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }
            else
            {
                Entry.Name = string.Empty;
            }

            long Next = Offset + ((Length + 7) & ~7L);

            if (ExtraStreams > 0)
                Next = SkipStreamEntries(Next, ExtraStreams, ref Entry);

            Offset = Next;
            return true;
        }

        private long SkipStreamEntries(long Offset, int Count, ref WimDirectoryEntry Entry)
        {
            Span<byte> Fixed = stackalloc byte[StreamEntryFixedSize];

            for (int i = 0; i < Count; i++)
            {
                Metadata.ReadExact(Offset, Fixed);

                long Length = (long)BinaryPrimitives.ReadUInt64LittleEndian(Fixed);
                if (Length < StreamEntryFixedSize)
                    throw new InvalidDataException($"A stream entry at offset {Offset} declares a length of {Length}.");

                int NameLength = BinaryPrimitives.ReadUInt16LittleEndian(Fixed.Slice(36));

                if (NameLength == 0 && Entry.Hash.IsZero)
                    Entry.Hash = new Sha1Hash(Fixed.Slice(16, 20));

                Offset += (Length + 7) & ~7L;
            }

            return Offset;
        }

        public WimBlob? FindBlob(in WimDirectoryEntry Entry)
        {
            return Reader.FindBlob(Entry.Hash);
        }

        public bool TryOpenFile(in WimDirectoryEntry Entry, out ImageDataSource File)
        {
            File = null!;

            WimBlob? Blob = Reader.FindBlob(Entry.Hash);
            if (Blob == null)
                return false;

            File = Reader.OpenBlob(Blob);
            return true;
        }

        public void Dispose()
        {
            Metadata.Dispose();
        }
    }
}
