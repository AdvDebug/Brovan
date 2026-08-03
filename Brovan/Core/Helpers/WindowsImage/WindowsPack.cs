using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal static class WindowsPackFormat
    {
        public const int HeaderSize = 56;
        public const int BlockSize = 128 * 1024;
        public const int BrotliQuality = 5;
        public const uint StoredFlag = 0x80000000;

        public static ReadOnlySpan<byte> Magic => "BRVPACK1"u8;
    }

    internal sealed class WindowsPackWriter : IDisposable
    {
        private readonly FileStream Output;
        private readonly List<uint> BlockLengths = new List<uint>();
        private readonly List<(string Name, long Offset, long Length)> Entries = new List<(string, long, long)>();
        private readonly Dictionary<Sha1Hash, (long Offset, long Length)> Deduplicated = new Dictionary<Sha1Hash, (long, long)>();
        private readonly byte[][] Blocks;
        private readonly byte[][] Compressed;
        private readonly int[] Written;
        private readonly int[] Sizes;

        private int Ready;
        private int Filled;
        private long LogicalLength;

        private readonly string FinalPath;
        private readonly string TemporaryPath;
        private bool Completed;

        public WindowsPackWriter(string Path)
        {
            FinalPath = Path;
            TemporaryPath = Path + ".part";
            Output = new FileStream(TemporaryPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
            Output.Write(new byte[WindowsPackFormat.HeaderSize]);

            int Batch = Math.Clamp(Environment.ProcessorCount, 1, 8);
            Blocks = new byte[Batch][];
            Compressed = new byte[Batch][];
            Written = new int[Batch];
            Sizes = new int[Batch];

            for (int i = 0; i < Batch; i++)
            {
                Blocks[i] = new byte[WindowsPackFormat.BlockSize];
                Compressed[i] = new byte[WindowsPackFormat.BlockSize + 1024];
            }
        }

        public bool TryAddDeduplicated(string Name, Sha1Hash Hash)
        {
            if (Hash.IsZero || !Deduplicated.TryGetValue(Hash, out (long Offset, long Length) Existing))
                return false;

            Entries.Add((Name, Existing.Offset, Existing.Length));
            return true;
        }

        public void Add(string Name, Sha1Hash Hash, ImageDataSource Source)
        {
            long Start = LogicalLength;
            long Remaining = Source.Length;
            long Position = 0;

            while (Remaining > 0)
            {
                int Space = WindowsPackFormat.BlockSize - Filled;
                int Count = (int)Math.Min(Space, Remaining);

                Source.ReadExact(Position, Blocks[Ready].AsSpan(Filled, Count));

                Filled += Count;
                Position += Count;
                Remaining -= Count;
                LogicalLength += Count;

                if (Filled == WindowsPackFormat.BlockSize)
                {
                    Sizes[Ready] = Filled;
                    Filled = 0;

                    if (++Ready == Blocks.Length)
                        FlushBatch();
                }
            }

            Entries.Add((Name, Start, Source.Length));

            if (!Hash.IsZero)
                Deduplicated[Hash] = (Start, Source.Length);
        }

        private void FlushBatch()
        {
            if (Filled != 0)
            {
                Sizes[Ready] = Filled;
                Filled = 0;
                Ready++;
            }

            if (Ready == 0)
                return;

            int Count = Ready;
            Ready = 0;

            if (Count == 1)
                CompressBlock(0);
            else
                Parallel.For(0, Count, CompressBlock);

            for (int i = 0; i < Count; i++)
            {
                if (Written[i] > 0)
                {
                    Output.Write(Compressed[i], 0, Written[i]);
                    BlockLengths.Add((uint)Written[i]);
                }
                else
                {
                    Output.Write(Blocks[i], 0, Sizes[i]);
                    BlockLengths.Add((uint)Sizes[i] | WindowsPackFormat.StoredFlag);
                }
            }
        }

        private void CompressBlock(int Index)
        {
            Written[Index] = BrotliEncoder.TryCompress(Blocks[Index].AsSpan(0, Sizes[Index]), Compressed[Index], out int Size, WindowsPackFormat.BrotliQuality, 18) && Size < Sizes[Index]
                ? Size
                : 0;
        }

        public void Complete()
        {
            FlushBatch();

            long BlockTableOffset = Output.Position;

            byte[] Table = ArrayPool<byte>.Shared.Rent(BlockLengths.Count * 4);

            try
            {
                for (int i = 0; i < BlockLengths.Count; i++)
                    BinaryPrimitives.WriteUInt32LittleEndian(Table.AsSpan(i * 4), BlockLengths[i]);

                Output.Write(Table, 0, BlockLengths.Count * 4);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Table);
            }

            long IndexOffset = Output.Position;

            Span<byte> Fixed = stackalloc byte[18];

            foreach ((string Name, long Offset, long Length) Entry in Entries)
            {
                byte[] Name = Encoding.UTF8.GetBytes(Entry.Name);

                BinaryPrimitives.WriteUInt16LittleEndian(Fixed, (ushort)Name.Length);
                BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(2), Entry.Offset);
                BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(10), Entry.Length);

                Output.Write(Fixed);
                Output.Write(Name);
            }

            Span<byte> Header = stackalloc byte[WindowsPackFormat.HeaderSize];
            WindowsPackFormat.Magic.CopyTo(Header);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(8), WindowsPackFormat.BlockSize);
            BinaryPrimitives.WriteInt64LittleEndian(Header.Slice(16), Entries.Count);
            BinaryPrimitives.WriteInt64LittleEndian(Header.Slice(24), BlockLengths.Count);
            BinaryPrimitives.WriteInt64LittleEndian(Header.Slice(32), IndexOffset);
            BinaryPrimitives.WriteInt64LittleEndian(Header.Slice(40), BlockTableOffset);
            BinaryPrimitives.WriteInt64LittleEndian(Header.Slice(48), LogicalLength);

            Output.Position = 0;
            Output.Write(Header);
            Output.Flush();
            Output.Dispose();

            File.Move(TemporaryPath, FinalPath, overwrite: true);
            Completed = true;
        }

        public void Dispose()
        {
            Output.Dispose();

            if (Completed)
                return;

            try
            {
                File.Delete(TemporaryPath);
            }
            catch (IOException)
            {
            }
        }
    }

    internal readonly struct WindowsPackEntry
    {
        public readonly long Offset;
        public readonly long Length;

        public WindowsPackEntry(long Offset, long Length)
        {
            this.Offset = Offset;
            this.Length = Length;
        }
    }

    /// <summary>
    /// Read side of the pack. Blocks are decompressed on demand into a bounded cache and never written back to disk.
    /// </summary>
    internal sealed class WindowsPackReader : IDisposable
    {
        private const long CacheBudget = 16L << 20;

        private readonly FileImageDataSource Source;
        private readonly Dictionary<string, WindowsPackEntry> Index = new Dictionary<string, WindowsPackEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<string>> Directories = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        private readonly long[] BlockOffsets;
        private readonly uint[] BlockLengths;
        private readonly int BlockSize;
        private readonly long LogicalLength;
        private readonly BlockCache Cache;
        private readonly object Lock = new object();

        public WindowsPackReader(string Path)
        {
            Source = new FileImageDataSource(Path);

            Span<byte> Header = stackalloc byte[WindowsPackFormat.HeaderSize];
            Source.ReadExact(0, Header);

            if (!Header.Slice(0, 8).SequenceEqual(WindowsPackFormat.Magic))
                throw new InvalidDataException($"'{Path}' is not a Brovan Windows pack.");

            BlockSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(8));
            long FileCount = BinaryPrimitives.ReadInt64LittleEndian(Header.Slice(16));
            long BlockCount = BinaryPrimitives.ReadInt64LittleEndian(Header.Slice(24));
            long IndexOffset = BinaryPrimitives.ReadInt64LittleEndian(Header.Slice(32));
            long BlockTableOffset = BinaryPrimitives.ReadInt64LittleEndian(Header.Slice(40));
            LogicalLength = BinaryPrimitives.ReadInt64LittleEndian(Header.Slice(48));

            BlockLengths = new uint[BlockCount];
            BlockOffsets = new long[BlockCount + 1];

            byte[] Table = ArrayPool<byte>.Shared.Rent((int)(BlockCount * 4));

            try
            {
                Span<byte> Raw = Table.AsSpan(0, (int)(BlockCount * 4));
                Source.ReadExact(BlockTableOffset, Raw);

                long Running = WindowsPackFormat.HeaderSize;

                for (long i = 0; i < BlockCount; i++)
                {
                    uint Entry = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice((int)i * 4));
                    BlockLengths[i] = Entry;
                    BlockOffsets[i] = Running;
                    Running += Entry & ~WindowsPackFormat.StoredFlag;
                }

                BlockOffsets[BlockCount] = Running;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Table);
            }

            long Position = IndexOffset;
            Span<byte> Fixed = stackalloc byte[18];

            for (long i = 0; i < FileCount; i++)
            {
                Source.ReadExact(Position, Fixed);

                int NameLength = BinaryPrimitives.ReadUInt16LittleEndian(Fixed);
                long Offset = BinaryPrimitives.ReadInt64LittleEndian(Fixed.Slice(2));
                long Length = BinaryPrimitives.ReadInt64LittleEndian(Fixed.Slice(10));

                byte[] Name = ArrayPool<byte>.Shared.Rent(NameLength);

                try
                {
                    Source.ReadExact(Position + 18, Name.AsSpan(0, NameLength));
                    string Key = Encoding.UTF8.GetString(Name, 0, NameLength);

                    Index[Key] = new WindowsPackEntry(Offset, Length);
                    Register(Key);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Name);
                }

                Position += 18 + NameLength;
            }

            int Capacity = (int)Math.Max(4, CacheBudget / BlockSize);
            Cache = new BlockCache(BlockSize, Capacity);
        }

        private void Register(string Name)
        {
            int Split = Name.LastIndexOf('/');
            string Directory = Split < 0 ? string.Empty : Name.Substring(0, Split);

            if (!Directories.TryGetValue(Directory, out List<string>? Names))
            {
                Names = new List<string>();
                Directories[Directory] = Names;
            }

            Names.Add(Name);
        }

        public bool TryGetEntry(string Name, out WindowsPackEntry Entry)
        {
            return Index.TryGetValue(Name, out Entry);
        }

        public bool DirectoryExists(string Name)
        {
            return Directories.ContainsKey(Name);
        }

        public IReadOnlyList<string> ListDirectory(string Name)
        {
            return Directories.TryGetValue(Name, out List<string>? Names) ? Names : Array.Empty<string>();
        }

        public int Read(in WindowsPackEntry Entry, long Offset, Span<byte> Buffer)
        {
            if (Offset >= Entry.Length || Buffer.Length == 0)
                return 0;

            long Available = Entry.Length - Offset;
            if (Buffer.Length > Available)
                Buffer = Buffer.Slice(0, (int)Available);

            long Logical = Entry.Offset + Offset;
            long Index = Logical / BlockSize;
            int Inside = (int)(Logical - (Index * BlockSize));

            lock (Lock)
            {
                if (!Cache.TryGet(Index, out ReadOnlySpan<byte> Block))
                {
                    DecodeBlock(Index);

                    if (!Cache.TryGet(Index, out Block))
                        return 0;
                }

                int Count = Math.Min(Buffer.Length, Block.Length - Inside);
                Block.Slice(Inside, Count).CopyTo(Buffer);
                return Count;
            }
        }

        public byte[] ReadAll(in WindowsPackEntry Entry)
        {
            byte[] Data = new byte[Entry.Length];

            int Total = 0;
            while (Total < Data.Length)
            {
                int Count = Read(Entry, Total, Data.AsSpan(Total));
                if (Count <= 0)
                    throw new EndOfStreamException("A pack entry ended before its declared length.");

                Total += Count;
            }

            return Data;
        }

        private void DecodeBlock(long Index)
        {
            uint Entry = BlockLengths[Index];
            int Stored = (int)(Entry & ~WindowsPackFormat.StoredFlag);
            int Size = (int)Math.Min(BlockSize, LogicalLength - (Index * BlockSize));

            if ((Entry & WindowsPackFormat.StoredFlag) != 0)
            {
                Span<byte> Target = Cache.Reserve(Index, Stored);
                Source.ReadExact(BlockOffsets[Index], Target);
                return;
            }

            byte[] Buffer = ArrayPool<byte>.Shared.Rent(Stored);

            try
            {
                Span<byte> Compressed = Buffer.AsSpan(0, Stored);
                Source.ReadExact(BlockOffsets[Index], Compressed);

                Span<byte> Target = Cache.Reserve(Index, Size);

                if (!BrotliDecoder.TryDecompress(Compressed, Target, out int Written) || Written != Size)
                    throw new InvalidDataException($"Pack block {Index} failed to decompress.");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        public void Dispose()
        {
            Cache.Dispose();
            Source.Dispose();
        }
    }
}
