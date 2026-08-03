using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal readonly struct Sha1Hash : IEquatable<Sha1Hash>
    {
        private readonly ulong Low;
        private readonly ulong High;
        private readonly uint Tail;

        public Sha1Hash(ReadOnlySpan<byte> Bytes)
        {
            Low = BinaryPrimitives.ReadUInt64LittleEndian(Bytes);
            High = BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(8));
            Tail = BinaryPrimitives.ReadUInt32LittleEndian(Bytes.Slice(16));
        }

        public bool IsZero => Low == 0 && High == 0 && Tail == 0;

        public bool Equals(Sha1Hash Other)
        {
            return Low == Other.Low && High == Other.High && Tail == Other.Tail;
        }

        public override bool Equals(object? Other)
        {
            return Other is Sha1Hash Hash && Equals(Hash);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Low, High, Tail);
        }
    }

    internal enum WimCompression
    {
        None = 0,
        Xpress = 1,
        Lzx = 2,
        Lzms = 3,
    }

    internal sealed class WimResource
    {
        public long Offset;
        public long CompressedSize;
        public long UncompressedSize;
        public byte Flags;
        public WimCompression Compression;
        public int ChunkSize;

        public bool IsCompressed => (Flags & 0x04) != 0;
        public bool IsSolid => (Flags & 0x10) != 0;
    }

    internal sealed class WimBlob
    {
        public Sha1Hash Hash;
        public WimResource Resource = null!;
        public long OffsetInResource;
        public long Size;
        public bool IsMetadata;
    }

    /// <summary>
    /// Reads the resource layout of a WIM or ESD. Every read goes through <see cref="ImageDataSource"/>, so the
    /// backing image may equally be a local file or a remote ISO served over range requests.
    /// </summary>
    internal sealed class WimReader : IDisposable
    {
        private const int HeaderSize = 208;
        private const int BlobEntrySize = 50;
        private const long SolidResourceMagic = 0x100000000L;

        private readonly ImageDataSource Source;
        private readonly bool OwnsSource;
        private readonly Dictionary<Sha1Hash, WimBlob> BlobsByHash = new Dictionary<Sha1Hash, WimBlob>();
        private readonly List<WimBlob> MetadataBlobs = new List<WimBlob>();
        private readonly Dictionary<WimResource, WimResourceSource> DecodedResources = new Dictionary<WimResource, WimResourceSource>();

        public WimCompression Compression { get; private set; }
        public int ChunkSize { get; private set; }
        public int ImageCount { get; private set; }

        public WimReader(ImageDataSource Source, bool OwnsSource = false)
        {
            this.Source = Source;
            this.OwnsSource = OwnsSource;

            Span<byte> Header = stackalloc byte[HeaderSize];
            Source.ReadExact(0, Header);

            if (!Header.Slice(0, 8).SequenceEqual("MSWIM\0\0\0"u8))
                throw new InvalidDataException("The image does not start with a WIM signature.");

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(16));
            ChunkSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(20));
            ImageCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(44));

            if ((Flags & 0x00000002) == 0)
                Compression = WimCompression.None;
            else if ((Flags & 0x00020000) != 0)
                Compression = WimCompression.Xpress;
            else if ((Flags & 0x00040000) != 0)
                Compression = WimCompression.Lzx;
            else if ((Flags & 0x00080000) != 0)
                Compression = WimCompression.Lzms;
            else
                throw new InvalidDataException($"The WIM declares compression but no known algorithm (flags 0x{Flags:X8}).");

            if (ChunkSize == 0)
                ChunkSize = 32768;

            ushort TotalParts = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(42));
            if (TotalParts > 1)
                throw new NotSupportedException("Split WIM images are not supported; supply the single file media instead.");

            WimResource BlobTable = ReadResourceHeader(Header.Slice(48));
            ReadBlobTable(BlobTable);
        }

        private WimResource ReadResourceHeader(ReadOnlySpan<byte> Raw)
        {
            long Size = 0;
            for (int i = 0; i < 7; i++)
                Size |= (long)Raw[i] << (i * 8);

            return new WimResource
            {
                CompressedSize = Size,
                Flags = Raw[7],
                Offset = (long)BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(8)),
                UncompressedSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(16)),
                Compression = Compression,
                ChunkSize = ChunkSize,
            };
        }

        private void ReadBlobTable(WimResource Table)
        {
            if (Table.UncompressedSize <= 0 || Table.UncompressedSize > int.MaxValue)
                throw new InvalidDataException($"The blob table declares an unusable size of {Table.UncompressedSize} bytes.");

            int Length = (int)Table.UncompressedSize;
            byte[] Buffer = ArrayPool<byte>.Shared.Rent(Length);

            try
            {
                using (ImageDataSource Reader = OpenResource(Table))
                    Reader.ReadExact(0, Buffer.AsSpan(0, Length));

                ReadOnlySpan<byte> Entries = Buffer.AsSpan(0, Length);
                int Count = Length / BlobEntrySize;

                List<WimResource> SolidResources = new List<WimResource>();
                List<WimBlob> SolidBlobs = new List<WimBlob>();

                for (int i = 0; i < Count; i++)
                {
                    ReadOnlySpan<byte> Entry = Entries.Slice(i * BlobEntrySize, BlobEntrySize);
                    WimResource Resource = ReadResourceHeader(Entry);
                    Sha1Hash Hash = new Sha1Hash(Entry.Slice(30, 20));

                    if (Resource.IsSolid)
                    {
                        // Within a solid run the resource headers and the blobs they hold are interleaved, so both
                        // are collected and only paired up once the run ends.
                        if (Resource.UncompressedSize == SolidResourceMagic)
                        {
                            SolidResources.Add(ReadSolidResourceHeader(Resource));
                            continue;
                        }

                        SolidBlobs.Add(new WimBlob
                        {
                            Hash = Hash,
                            OffsetInResource = Resource.Offset,
                            Size = Resource.CompressedSize,
                        });

                        continue;
                    }

                    ResolveSolidGroup(SolidResources, SolidBlobs);

                    WimBlob Blob = new WimBlob
                    {
                        Hash = Hash,
                        Resource = Resource,
                        OffsetInResource = 0,
                        Size = Resource.UncompressedSize,
                        IsMetadata = (Resource.Flags & 0x02) != 0,
                    };

                    if (Blob.IsMetadata)
                        MetadataBlobs.Add(Blob);
                    else
                        AddBlob(Blob);
                }

                ResolveSolidGroup(SolidResources, SolidBlobs);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        /// <summary>
        /// Assigns the blobs of one solid run to the resources of that run. Blob offsets address the run's resources
        /// as if their uncompressed contents were concatenated in the order the headers appear.
        /// </summary>
        private void ResolveSolidGroup(List<WimResource> Resources, List<WimBlob> Blobs)
        {
            if (Blobs.Count != 0 && Resources.Count == 0)
                throw new InvalidDataException("A solid run declares packed blobs but no solid resource.");

            for (int i = 0; i < Blobs.Count; i++)
            {
                WimBlob Blob = Blobs[i];
                long Offset = Blob.OffsetInResource;
                WimResource? Container = null;

                for (int s = 0; s < Resources.Count; s++)
                {
                    if (Offset < Resources[s].UncompressedSize)
                    {
                        Container = Resources[s];
                        break;
                    }

                    Offset -= Resources[s].UncompressedSize;
                }

                if (Container == null)
                    throw new InvalidDataException($"A packed blob at offset {Blob.OffsetInResource} falls outside every solid resource of its run.");

                Blob.Resource = Container;
                Blob.OffsetInResource = Offset;
                AddBlob(Blob);
            }

            Resources.Clear();
            Blobs.Clear();
        }

        private void AddBlob(WimBlob Blob)
        {
            if (!Blob.Hash.IsZero)
                BlobsByHash.TryAdd(Blob.Hash, Blob);
        }

        private WimResource ReadSolidResourceHeader(WimResource Resource)
        {
            Span<byte> Header = stackalloc byte[16];
            Source.ReadExact(Resource.Offset, Header);

            Resource.UncompressedSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(Header);
            Resource.ChunkSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(8));
            Resource.Compression = (WimCompression)BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(12));

            if (Resource.ChunkSize <= 0)
                throw new InvalidDataException($"A solid resource declares a chunk size of {Resource.ChunkSize}.");

            return Resource;
        }

        public WimBlob? FindBlob(Sha1Hash Hash)
        {
            return BlobsByHash.TryGetValue(Hash, out WimBlob? Blob) ? Blob : null;
        }

        /// <summary>
        /// Opens one blob. The decoder for a compressed resource is kept alive across blobs: a solid resource holds
        /// thousands of files in one chunk stream, so discarding its chunk cache between files would re-decode the
        /// same chunks over and over.
        /// </summary>
        public ImageDataSource OpenBlob(WimBlob Blob)
        {
            WimResource Resource = Blob.Resource;

            if (!Resource.IsCompressed && !Resource.IsSolid)
                return new WindowImageDataSource(Source, Resource.Offset + Blob.OffsetInResource, Blob.Size);

            if (!DecodedResources.TryGetValue(Resource, out WimResourceSource? Decoded))
            {
                Decoded = new WimResourceSource(Source, Resource);
                DecodedResources[Resource] = Decoded;
            }

            return new WindowImageDataSource(Decoded, Blob.OffsetInResource, Blob.Size);
        }

        /// <summary>
        /// Drops the cached decoders. Only safe once every source handed out by <see cref="OpenBlob"/> has been
        /// disposed, so the caller decides when: the importer calls it when it moves on to another resource, which
        /// keeps at most one solid resource's chunk cache alive at a time.
        /// </summary>
        public void ReleaseDecoders()
        {
            foreach (WimResourceSource Decoded in DecodedResources.Values)
                Decoded.Dispose();

            DecodedResources.Clear();
        }

        public WimBlob? FindBlob(in WimDirectoryEntry Entry)
        {
            return FindBlob(Entry.Hash);
        }

        public ImageDataSource OpenResource(WimResource Resource)
        {
            if (!Resource.IsCompressed && !Resource.IsSolid)
                return new WindowImageDataSource(Source, Resource.Offset, Resource.UncompressedSize);

            return new WimResourceSource(Source, Resource);
        }

        public WimImage OpenImage(int Index)
        {
            if (Index < 1 || Index > MetadataBlobs.Count)
                throw new ArgumentOutOfRangeException(nameof(Index), $"The image has {MetadataBlobs.Count} metadata resources; {Index} was requested.");

            return new WimImage(this, OpenBlob(MetadataBlobs[Index - 1]));
        }

        public void Dispose()
        {
            foreach (WimResourceSource Decoded in DecodedResources.Values)
                Decoded.Dispose();

            DecodedResources.Clear();

            if (OwnsSource)
                Source.Dispose();
        }
    }

    /// <summary>
    /// Decompresses a WIM resource chunk by chunk on demand. Only the chunks a caller actually touches are decoded,
    /// which keeps a multi gigabyte solid resource usable without ever materializing it.
    /// </summary>
    internal sealed class WimResourceSource : ImageDataSource
    {
        /// <summary>
        /// Memory the chunk cache and the parallel decode may occupy together. Solid chunks are tens of megabytes,
        /// so this is what decides how many of them can be decoded at once; it is derived from the machine so a
        /// phone does not try to hold the same working set as a desktop.
        /// </summary>
        private static readonly long CacheBudget = Math.Clamp(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 32, 32L << 20, 192L << 20);

        private readonly ImageDataSource Source;
        private readonly WimResource Resource;
        private readonly long[] ChunkOffsets;
        private readonly long DataStart;
        private readonly int ChunkSize;
        private readonly BlockCache Cache;
        private readonly WimDecompressor[] Decompressors;

        public WimResourceSource(ImageDataSource Source, WimResource Resource)
        {
            this.Source = Source;
            this.Resource = Resource;
            ChunkSize = Resource.ChunkSize;

            int Count = (int)((Resource.UncompressedSize + ChunkSize - 1) / ChunkSize);
            if (Count <= 0)
                Count = 1;

            ChunkOffsets = new long[Count + 1];
            DataStart = ReadChunkTable(Count);

            int Capacity = (int)Math.Clamp(CacheBudget / ChunkSize, 1, 32);
            Cache = new BlockCache(ChunkSize, Capacity);

            int Workers = (int)Math.Clamp(Math.Min(Environment.ProcessorCount, CacheBudget / ChunkSize), 1, 8);
            Decompressors = new WimDecompressor[Workers];

            for (int i = 0; i < Workers; i++)
                Decompressors[i] = new WimDecompressor(Resource.Compression, ChunkSize);
        }

        public override long Length => Resource.UncompressedSize;

        private long ReadChunkTable(int Count)
        {
            if (Resource.IsSolid)
            {
                int TableBytes = Count * 4;
                byte[] Buffer = ArrayPool<byte>.Shared.Rent(TableBytes);

                try
                {
                    Span<byte> Table = Buffer.AsSpan(0, TableBytes);
                    Source.ReadExact(Resource.Offset + 16, Table);

                    long Running = 0;
                    for (int i = 0; i < Count; i++)
                    {
                        ChunkOffsets[i] = Running;
                        Running += BinaryPrimitives.ReadUInt32LittleEndian(Table.Slice(i * 4));
                    }

                    ChunkOffsets[Count] = Running;
                    return Resource.Offset + 16 + TableBytes;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }

            int EntrySize = Resource.UncompressedSize > uint.MaxValue ? 8 : 4;
            int Entries = Count - 1;
            int Bytes = Entries * EntrySize;

            ChunkOffsets[0] = 0;

            if (Entries > 0)
            {
                byte[] Buffer = ArrayPool<byte>.Shared.Rent(Bytes);

                try
                {
                    Span<byte> Table = Buffer.AsSpan(0, Bytes);
                    Source.ReadExact(Resource.Offset, Table);

                    for (int i = 0; i < Entries; i++)
                    {
                        ChunkOffsets[i + 1] = EntrySize == 4
                            ? BinaryPrimitives.ReadUInt32LittleEndian(Table.Slice(i * 4))
                            : (long)BinaryPrimitives.ReadUInt64LittleEndian(Table.Slice(i * 8));
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }

            ChunkOffsets[Count] = Resource.CompressedSize - Bytes;
            return Resource.Offset + Bytes;
        }

        public override int Read(long Offset, Span<byte> Buffer)
        {
            if (Offset >= Resource.UncompressedSize || Buffer.Length == 0)
                return 0;

            long Index = Offset / ChunkSize;
            int Inside = (int)(Offset - (Index * ChunkSize));

            if (!Cache.TryGet(Index, out ReadOnlySpan<byte> Chunk))
            {
                DecodeChunk(Index);

                if (!Cache.TryGet(Index, out Chunk))
                    return 0;
            }

            int Count = Math.Min(Buffer.Length, Chunk.Length - Inside);
            Chunk.Slice(Inside, Count).CopyTo(Buffer);
            return Count;
        }

        private void DecodeChunk(long Index)
        {
            int Count = Decompressors.Length;
            long Chunks = ChunkOffsets.LongLength - 1;

            if (Index + Count > Chunks)
                Count = (int)(Chunks - Index);

            if (Count <= 1)
            {
                Span<byte> Single = Cache.Reserve(Index, ChunkLength(Index));
                DecodeInto(Index, Single, Decompressors[0]);
                return;
            }

            byte[][] Buffers = new byte[Count][];

            try
            {
                for (int i = 0; i < Count; i++)
                    Buffers[i] = ArrayPool<byte>.Shared.Rent(ChunkSize);

                Parallel.For(0, Count, i => DecodeInto(Index + i, Buffers[i].AsSpan(0, ChunkLength(Index + i)), Decompressors[i]));

                for (int i = 0; i < Count; i++)
                {
                    int Length = ChunkLength(Index + i);
                    Buffers[i].AsSpan(0, Length).CopyTo(Cache.Reserve(Index + i, Length));
                }
            }
            finally
            {
                for (int i = 0; i < Count; i++)
                {
                    if (Buffers[i] != null)
                        ArrayPool<byte>.Shared.Return(Buffers[i]);
                }
            }
        }

        private int ChunkLength(long Index)
        {
            return (int)Math.Min(ChunkSize, Resource.UncompressedSize - (Index * ChunkSize));
        }

        private void DecodeInto(long Index, Span<byte> Target, WimDecompressor Decompressor)
        {
            long CompressedStart = ChunkOffsets[Index];
            int CompressedSize = (int)(ChunkOffsets[Index + 1] - CompressedStart);

            if (CompressedSize <= 0 || CompressedSize > Target.Length + 4096)
                throw new InvalidDataException($"Chunk {Index} declares a compressed size of {CompressedSize} against an uncompressed size of {Target.Length}.");

            if (CompressedSize == Target.Length)
            {
                Source.ReadExact(DataStart + CompressedStart, Target);
                return;
            }

            Span<byte> Compressed = Decompressor.RentInput(CompressedSize);
            Source.ReadExact(DataStart + CompressedStart, Compressed);

            if (!Decompressor.Decompress(Compressed, Target))
                throw new InvalidDataException($"Chunk {Index} of a {Resource.Compression} resource failed to decompress.");
        }

        public override void Dispose()
        {
            Cache.Dispose();
        }
    }

    internal sealed class WimDecompressor
    {
        private byte[] Input = Array.Empty<byte>();
        private readonly WimCompression Compression;
        private readonly XpressDecompressor? Xpress;
        private readonly LzxDecompressor? Lzx;
        private readonly LzmsDecompressor? Lzms;

        public WimDecompressor(WimCompression Compression, int ChunkSize)
        {
            this.Compression = Compression;

            switch (Compression)
            {
                case WimCompression.Xpress:
                    Xpress = new XpressDecompressor();
                    break;
                case WimCompression.Lzx:
                    Lzx = new LzxDecompressor(ChunkSize);
                    break;
                case WimCompression.Lzms:
                    Lzms = new LzmsDecompressor();
                    break;
            }
        }

        /// <summary>
        /// Scratch space for one compressed chunk. A solid chunk runs to tens of megabytes, which is far past what
        /// the shared array pool retains, so the buffer is kept per decompressor instead of rented per chunk.
        /// </summary>
        public Span<byte> RentInput(int Length)
        {
            if (Input.Length < Length)
                Input = new byte[Length];

            return Input.AsSpan(0, Length);
        }

        public bool Decompress(ReadOnlySpan<byte> Input, Span<byte> Output)
        {
            return Compression switch
            {
                WimCompression.Xpress => Xpress!.Decompress(Input, Output),
                WimCompression.Lzx => Lzx!.Decompress(Input, Output),
                WimCompression.Lzms => Lzms!.Decompress(Input, Output),
                _ => false,
            };
        }
    }
}
