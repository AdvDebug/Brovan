using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal sealed class IsoReader
    {
        private const int SectorSize = 2048;

        private readonly ImageDataSource Source;
        private readonly UdfVolume Udf;

        private IsoReader(ImageDataSource Source, UdfVolume Udf)
        {
            this.Source = Source;
            this.Udf = Udf;
        }

        public static IsoReader Open(ImageDataSource Source)
        {
            UdfVolume? Udf = UdfVolume.TryOpen(Source);
            if (Udf == null)
                throw new InvalidDataException("The image is not a UDF volume.");

            return new IsoReader(Source, Udf);
        }

        public bool TryOpenFile(string Path, out ImageDataSource File)
        {
            return Udf.TryOpenFile(Source, Path, out File);
        }

        internal static string[] SplitPath(string Path)
        {
            return Path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        }

        private sealed class UdfVolume
        {
            private const int TagFileSetDescriptor = 256;
            private const int TagFileIdentifierDescriptor = 257;
            private const int TagAllocationExtentDescriptor = 258;
            private const int TagFileEntry = 261;
            private const int TagExtendedFileEntry = 266;

            private readonly uint PartitionStart;
            private readonly uint BlockSize;
            private readonly uint RootBlock;

            private UdfVolume(uint PartitionStart, uint BlockSize, uint RootBlock)
            {
                this.PartitionStart = PartitionStart;
                this.BlockSize = BlockSize;
                this.RootBlock = RootBlock;
            }

            public static UdfVolume? TryOpen(ImageDataSource Source)
            {
                try
                {
                    if (!HasUdfRecognitionSequence(Source))
                        return null;

                    byte[] Buffer = ArrayPool<byte>.Shared.Rent(SectorSize);

                    try
                    {
                        Span<byte> Anchor = Buffer.AsSpan(0, SectorSize);
                        Source.ReadExact(256L * SectorSize, Anchor);

                        if (BinaryPrimitives.ReadUInt16LittleEndian(Anchor) != 2)
                            return null;

                        uint SequenceLength = BinaryPrimitives.ReadUInt32LittleEndian(Anchor.Slice(16));
                        uint SequenceLocation = BinaryPrimitives.ReadUInt32LittleEndian(Anchor.Slice(20));

                        uint PartitionStart = uint.MaxValue;
                        uint BlockSize = SectorSize;
                        uint FileSetBlock = uint.MaxValue;
                        uint FileSetPartition = 0;

                        uint Sectors = SequenceLength / SectorSize;

                        for (uint i = 0; i < Sectors; i++)
                        {
                            Span<byte> Descriptor = Buffer.AsSpan(0, SectorSize);
                            Source.ReadExact((long)(SequenceLocation + i) * SectorSize, Descriptor);

                            ushort Tag = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor);

                            if (Tag == 8)
                                break;

                            if (Tag == 5)
                            {
                                PartitionStart = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(188));
                                continue;
                            }

                            if (Tag == 6)
                            {
                                BlockSize = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(212));
                                FileSetBlock = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(248 + 4));
                                FileSetPartition = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(248 + 8));
                            }
                        }

                        if (PartitionStart == uint.MaxValue || FileSetBlock == uint.MaxValue || BlockSize == 0)
                            return null;

                        if (FileSetPartition != 0)
                            throw new NotSupportedException($"The UDF volume references partition {FileSetPartition}; only single partition media is supported.");

                        Span<byte> FileSet = Buffer.AsSpan(0, SectorSize);
                        Source.ReadExact((long)(PartitionStart + FileSetBlock) * BlockSize, FileSet);

                        if (BinaryPrimitives.ReadUInt16LittleEndian(FileSet) != TagFileSetDescriptor)
                            return null;

                        uint RootBlock = BinaryPrimitives.ReadUInt32LittleEndian(FileSet.Slice(400 + 4));
                        return new UdfVolume(PartitionStart, BlockSize, RootBlock);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(Buffer);
                    }
                }
                catch (Exception Error) when (Error is IOException || Error is EndOfStreamException)
                {
                    return null;
                }
            }

            private static bool HasUdfRecognitionSequence(ImageDataSource Source)
            {
                byte[] Buffer = ArrayPool<byte>.Shared.Rent(SectorSize);

                try
                {
                    for (int Index = 16; Index < 32; Index++)
                    {
                        long Offset = (long)Index * SectorSize;
                        if (Offset + SectorSize > Source.Length)
                            return false;

                        Span<byte> Sector = Buffer.AsSpan(0, SectorSize);
                        Source.ReadExact(Offset, Sector);

                        ReadOnlySpan<byte> Identifier = Sector.Slice(1, 5);

                        if (Identifier.SequenceEqual("NSR02"u8) || Identifier.SequenceEqual("NSR03"u8))
                            return true;
                    }

                    return false;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }

            public bool TryOpenFile(ImageDataSource Source, string Path, out ImageDataSource File)
            {
                File = null!;

                string[] Parts = SplitPath(Path);
                if (Parts.Length == 0)
                    return false;

                uint Block = RootBlock;

                for (int i = 0; i < Parts.Length; i++)
                {
                    FileEntry Entry = ReadFileEntry(Source, Block);

                    if (i == Parts.Length - 1)
                    {
                        if (!TryFindChild(Source, Entry, Parts[i], out uint ChildBlock))
                            return false;

                        FileEntry Child = ReadFileEntry(Source, ChildBlock);
                        File = OpenEntry(Source, Child);
                        return true;
                    }

                    if (!TryFindChild(Source, Entry, Parts[i], out Block))
                        return false;
                }

                return false;
            }

            private ImageDataSource OpenEntry(ImageDataSource Source, FileEntry Entry)
            {
                if (Entry.InlineData != null)
                    return new MemoryImageDataSource(Entry.InlineData);

                ImageExtent[] Extents = new ImageExtent[Entry.Extents.Count];
                long Logical = 0;

                for (int i = 0; i < Extents.Length; i++)
                {
                    UdfExtent Extent = Entry.Extents[i];
                    Extents[i] = new ImageExtent((long)(PartitionStart + Extent.Block) * BlockSize, Logical, Extent.Length);
                    Logical += Extent.Length;
                }

                return new ExtentImageDataSource(Source, Extents, Math.Min(Entry.InformationLength, Logical));
            }

            private bool TryFindChild(ImageDataSource Source, FileEntry Directory, string Name, out uint Block)
            {
                Block = 0;

                long Length = Directory.InformationLength;
                if (Length <= 0 || Length > int.MaxValue)
                    return false;

                byte[] Data = ArrayPool<byte>.Shared.Rent((int)Length);

                try
                {
                    Span<byte> Content = Data.AsSpan(0, (int)Length);

                    using (ImageDataSource Reader = OpenEntry(Source, Directory))
                        Reader.ReadExact(0, Content);

                    int Offset = 0;

                    while (Offset + 38 <= Content.Length)
                    {
                        ReadOnlySpan<byte> Descriptor = Content.Slice(Offset);

                        if (BinaryPrimitives.ReadUInt16LittleEndian(Descriptor) != TagFileIdentifierDescriptor)
                            return false;

                        byte Characteristics = Descriptor[18];
                        int NameLength = Descriptor[19];
                        int ImplementationLength = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(36));
                        int Total = 38 + ImplementationLength + NameLength;
                        int Padded = (Total + 3) & ~3;

                        if (Offset + Total > Content.Length)
                            return false;

                        if ((Characteristics & 0x08) == 0 && NameLength > 0)
                        {
                            ReadOnlySpan<byte> Raw = Descriptor.Slice(38 + ImplementationLength, NameLength);

                            if (MatchesDString(Raw, Name))
                            {
                                Block = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(20 + 4));
                                return true;
                            }
                        }

                        Offset += Padded;
                    }

                    return false;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Data);
                }
            }

            private static bool MatchesDString(ReadOnlySpan<byte> Raw, string Name)
            {
                byte Encoding = Raw[0];
                ReadOnlySpan<byte> Body = Raw.Slice(1);

                if (Encoding == 8)
                {
                    if (Body.Length != Name.Length)
                        return false;

                    for (int i = 0; i < Body.Length; i++)
                    {
                        if (char.ToUpperInvariant((char)Body[i]) != char.ToUpperInvariant(Name[i]))
                            return false;
                    }

                    return true;
                }

                if (Encoding != 16 || (Body.Length & 1) != 0 || Body.Length / 2 != Name.Length)
                    return false;

                for (int i = 0; i < Name.Length; i++)
                {
                    char Character = (char)((Body[i * 2] << 8) | Body[(i * 2) + 1]);
                    if (char.ToUpperInvariant(Character) != char.ToUpperInvariant(Name[i]))
                        return false;
                }

                return true;
            }

            private readonly struct UdfExtent
            {
                public readonly uint Block;
                public readonly long Length;

                public UdfExtent(uint Block, long Length)
                {
                    this.Block = Block;
                    this.Length = Length;
                }
            }

            private sealed class FileEntry
            {
                public long InformationLength;
                public List<UdfExtent> Extents = new List<UdfExtent>();
                public byte[]? InlineData;
            }

            private FileEntry ReadFileEntry(ImageDataSource Source, uint Block)
            {
                byte[] Buffer = ArrayPool<byte>.Shared.Rent((int)BlockSize);

                try
                {
                    Span<byte> Descriptor = Buffer.AsSpan(0, (int)BlockSize);
                    Source.ReadExact((long)(PartitionStart + Block) * BlockSize, Descriptor);

                    ushort Tag = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor);
                    int Base;

                    if (Tag == TagFileEntry)
                        Base = 176;
                    else if (Tag == TagExtendedFileEntry)
                        Base = 216;
                    else
                        throw new InvalidDataException($"Expected a UDF file entry at block {Block}, found tag {Tag}.");

                    ushort Flags = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(16 + 18));
                    int DescriptorType = Flags & 0x07;

                    FileEntry Entry = new FileEntry
                    {
                        InformationLength = (long)BinaryPrimitives.ReadUInt64LittleEndian(Descriptor.Slice(56)),
                    };

                    int ExtendedAttributeLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(Base - 8));
                    int AllocationLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(Base - 4));
                    int AllocationOffset = Base + ExtendedAttributeLength;

                    if (AllocationOffset + AllocationLength > Descriptor.Length)
                        throw new InvalidDataException($"The UDF file entry at block {Block} declares {AllocationLength} bytes of allocation descriptors that do not fit in one block.");

                    if (DescriptorType == 3)
                    {
                        Entry.InlineData = Descriptor.Slice(AllocationOffset, AllocationLength).ToArray();
                        Entry.InformationLength = Math.Min(Entry.InformationLength, AllocationLength);
                        return Entry;
                    }

                    ReadAllocationDescriptors(Source, Descriptor.Slice(AllocationOffset, AllocationLength), DescriptorType, Entry);
                    return Entry;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }

            private void ReadAllocationDescriptors(ImageDataSource Source, ReadOnlySpan<byte> Descriptors, int DescriptorType, FileEntry Entry)
            {
                int Stride = DescriptorType == 0 ? 8 : 16;
                int Offset = 0;

                while (Offset + Stride <= Descriptors.Length)
                {
                    uint Raw = BinaryPrimitives.ReadUInt32LittleEndian(Descriptors.Slice(Offset));
                    uint Block = BinaryPrimitives.ReadUInt32LittleEndian(Descriptors.Slice(Offset + 4));

                    long Length = Raw & 0x3FFFFFFF;
                    int Type = (int)(Raw >> 30);

                    Offset += Stride;

                    if (Type == 3)
                    {
                        ReadAllocationExtent(Source, Block, (int)Length, DescriptorType, Entry);
                        return;
                    }

                    if (Length == 0)
                        continue;

                    if (Type == 0)
                        Entry.Extents.Add(new UdfExtent(Block, Length));
                }
            }

            private void ReadAllocationExtent(ImageDataSource Source, uint Block, int Length, int DescriptorType, FileEntry Entry)
            {
                byte[] Buffer = ArrayPool<byte>.Shared.Rent((int)BlockSize);

                try
                {
                    Span<byte> Descriptor = Buffer.AsSpan(0, (int)BlockSize);
                    Source.ReadExact((long)(PartitionStart + Block) * BlockSize, Descriptor);

                    if (BinaryPrimitives.ReadUInt16LittleEndian(Descriptor) != TagAllocationExtentDescriptor)
                        throw new InvalidDataException($"Expected a UDF allocation extent descriptor at block {Block}.");

                    int Available = (int)BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(20));
                    if (Length > 0 && Length - 24 < Available)
                        Available = Length - 24;

                    if (24 + Available > Descriptor.Length)
                        throw new InvalidDataException($"The UDF allocation extent at block {Block} does not fit in one block.");

                    ReadAllocationDescriptors(Source, Descriptor.Slice(24, Available), DescriptorType, Entry);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }
        }
    }

    internal sealed class MemoryImageDataSource : ImageDataSource
    {
        private readonly byte[] Data;

        public MemoryImageDataSource(byte[] Data)
        {
            this.Data = Data;
        }

        public override long Length => Data.Length;

        public override int Read(long Offset, Span<byte> Buffer)
        {
            if (Offset >= Data.Length)
                return 0;

            int Count = (int)Math.Min(Buffer.Length, Data.Length - Offset);
            Data.AsSpan((int)Offset, Count).CopyTo(Buffer);
            return Count;
        }
    }
}
