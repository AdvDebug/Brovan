using System;
using System.Buffers;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal abstract class ImageDataSource : IDisposable
    {
        public abstract long Length { get; }

        public abstract int Read(long Offset, Span<byte> Buffer);

        public void ReadExact(long Offset, Span<byte> Buffer)
        {
            int Total = 0;

            while (Total < Buffer.Length)
            {
                int Count = Read(Offset + Total, Buffer.Slice(Total));
                if (Count <= 0)
                    throw new EndOfStreamException($"Truncated read at offset {Offset + Total} ({Buffer.Length - Total} bytes missing).");

                Total += Count;
            }
        }

        public virtual void Dispose()
        {
        }
    }

    internal sealed class FileImageDataSource : ImageDataSource
    {
        private readonly SafeFileHandle Handle;
        private readonly long FileLength;
        private readonly bool OwnsHandle;

        public FileImageDataSource(string Path)
        {
            Handle = File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, FileOptions.RandomAccess);
            FileLength = RandomAccess.GetLength(Handle);
            OwnsHandle = true;
        }

        public FileImageDataSource(SafeFileHandle Handle, long Length)
        {
            this.Handle = Handle;
            FileLength = Length;
            OwnsHandle = false;
        }

        public override long Length => FileLength;

        public override int Read(long Offset, Span<byte> Buffer)
        {
            if (Offset >= FileLength)
                return 0;

            return RandomAccess.Read(Handle, Buffer, Offset);
        }

        public override void Dispose()
        {
            if (OwnsHandle)
                Handle.Dispose();
        }
    }

    /// <summary>
    /// Presents a contiguous window of another source as a source of its own.
    /// </summary>
    internal sealed class WindowImageDataSource : ImageDataSource
    {
        private readonly ImageDataSource Inner;
        private readonly long Start;
        private readonly long WindowLength;
        private readonly bool OwnsInner;

        public WindowImageDataSource(ImageDataSource Inner, long Start, long Length, bool OwnsInner = false)
        {
            this.Inner = Inner;
            this.Start = Start;
            WindowLength = Length;
            this.OwnsInner = OwnsInner;
        }

        public override long Length => WindowLength;

        public override int Read(long Offset, Span<byte> Buffer)
        {
            if (Offset >= WindowLength)
                return 0;

            long Available = WindowLength - Offset;
            if (Buffer.Length > Available)
                Buffer = Buffer.Slice(0, (int)Available);

            return Inner.Read(Start + Offset, Buffer);
        }

        public override void Dispose()
        {
            if (OwnsInner)
                Inner.Dispose();
        }
    }

    internal readonly struct ImageExtent
    {
        public readonly long SourceOffset;
        public readonly long LogicalOffset;
        public readonly long Length;

        public ImageExtent(long SourceOffset, long LogicalOffset, long Length)
        {
            this.SourceOffset = SourceOffset;
            this.LogicalOffset = LogicalOffset;
            this.Length = Length;
        }
    }

    /// <summary>
    /// Presents a fragmented file (a UDF file with several allocation extents) as one flat source.
    /// </summary>
    internal sealed class ExtentImageDataSource : ImageDataSource
    {
        private readonly ImageDataSource Inner;
        private readonly ImageExtent[] Extents;
        private readonly long TotalLength;

        public ExtentImageDataSource(ImageDataSource Inner, ImageExtent[] Extents, long Length)
        {
            this.Inner = Inner;
            this.Extents = Extents;
            TotalLength = Length;
        }

        public override long Length => TotalLength;

        public override int Read(long Offset, Span<byte> Buffer)
        {
            if (Offset >= TotalLength || Buffer.Length == 0)
                return 0;

            int Index = FindExtent(Offset);
            if (Index < 0)
                return 0;

            ImageExtent Extent = Extents[Index];
            long Inside = Offset - Extent.LogicalOffset;
            long Available = Extent.Length - Inside;

            if (Buffer.Length > Available)
                Buffer = Buffer.Slice(0, (int)Available);

            return Inner.Read(Extent.SourceOffset + Inside, Buffer);
        }

        private int FindExtent(long Offset)
        {
            int Low = 0;
            int High = Extents.Length - 1;

            while (Low <= High)
            {
                int Middle = (int)(((uint)Low + (uint)High) >> 1);
                ImageExtent Extent = Extents[Middle];

                if (Offset < Extent.LogicalOffset)
                    High = Middle - 1;
                else if (Offset >= Extent.LogicalOffset + Extent.Length)
                    Low = Middle + 1;
                else
                    return Middle;
            }

            return -1;
        }
    }

    /// <summary>
    /// Caches fixed size blocks of a slow source so the readers can seek freely without re-fetching.
    /// </summary>
    internal sealed class BlockCache : IDisposable
    {
        private readonly int BlockSize;
        private readonly int Capacity;
        private readonly long[] BlockNumbers;
        private readonly byte[]?[] Blocks;
        private readonly int[] BlockLengths;
        private readonly int[] LastUse;
        private int Clock;

        public BlockCache(int BlockSize, int Capacity)
        {
            this.BlockSize = BlockSize;
            this.Capacity = Capacity;
            BlockNumbers = new long[Capacity];
            Blocks = new byte[Capacity][];
            BlockLengths = new int[Capacity];
            LastUse = new int[Capacity];

            for (int i = 0; i < Capacity; i++)
                BlockNumbers[i] = -1;
        }

        public bool TryGet(long BlockNumber, out ReadOnlySpan<byte> Data)
        {
            for (int i = 0; i < Capacity; i++)
            {
                if (BlockNumbers[i] != BlockNumber)
                    continue;

                LastUse[i] = ++Clock;
                Data = new ReadOnlySpan<byte>(Blocks[i], 0, BlockLengths[i]);
                return true;
            }

            Data = default;
            return false;
        }

        public Span<byte> Reserve(long BlockNumber, int Length)
        {
            int Slot = -1;

            for (int i = 0; i < Capacity; i++)
            {
                if (BlockNumbers[i] == -1)
                {
                    Slot = i;
                    break;
                }
            }

            if (Slot < 0)
            {
                int Oldest = int.MaxValue;
                for (int i = 0; i < Capacity; i++)
                {
                    if (LastUse[i] < Oldest)
                    {
                        Oldest = LastUse[i];
                        Slot = i;
                    }
                }
            }

            byte[]? Buffer = Blocks[Slot];
            if (Buffer == null)
            {
                Buffer = ArrayPool<byte>.Shared.Rent(BlockSize);
                Blocks[Slot] = Buffer;
            }

            BlockNumbers[Slot] = BlockNumber;
            BlockLengths[Slot] = Length;
            LastUse[Slot] = ++Clock;
            return new Span<byte>(Buffer, 0, Length);
        }

        public void Invalidate()
        {
            for (int i = 0; i < Capacity; i++)
                BlockNumbers[i] = -1;
        }

        public void Dispose()
        {
            for (int i = 0; i < Capacity; i++)
            {
                byte[]? Buffer = Blocks[i];
                if (Buffer == null)
                    continue;

                Blocks[i] = null;
                BlockNumbers[i] = -1;
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }
    }
}
