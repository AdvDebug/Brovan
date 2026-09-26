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
                                FileSetBlock = ReadBlockAddress(Descriptor.Slice(248 + 4));
                            }
                        }

                        if (PartitionStart == uint.MaxValue || FileSetBlock == uint.MaxValue)
                            return null;

                        // UDF 2.2.4.2. The logical block size is the logical sector size.
                        if (BlockSize != SectorSize)
                            throw new NotSupportedException($"The UDF volume uses {BlockSize} byte logical blocks; only {SectorSize} byte blocks are supported.");

                        Span<byte> FileSet = Buffer.AsSpan(0, SectorSize);
                        Source.ReadExact((long)(PartitionStart + FileSetBlock) * BlockSize, FileSet);

                        if (BinaryPrimitives.ReadUInt16LittleEndian(FileSet) != TagFileSetDescriptor)
                            return null;

                        uint RootBlock = ReadBlockAddress(FileSet.Slice(400 + 4));
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

                for (int i = 0; i < Extents.Length; i++)
                {
                    UdfExtent Extent = Entry.Extents[i];
                    Extents[i] = new ImageExtent((long)(PartitionStart + Extent.Block) * BlockSize, Extent.LogicalOffset, Extent.Length);
                }

                return new ExtentImageDataSource(Source, Extents, Math.Min(Entry.InformationLength, Entry.LogicalLength));
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

                        // ECMA-167 4/14.4.3. Skip deleted (bit 2) and parent (bit 3) entries.
                        if ((Characteristics & 0x0C) == 0 && NameLength > 0)
                        {
                            ReadOnlySpan<byte> Raw = Descriptor.Slice(38 + ImplementationLength, NameLength);

                            if (MatchesDString(Raw, Name))
                            {
                                Block = ReadBlockAddress(Descriptor.Slice(20 + 4));
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

            private static uint ReadBlockAddress(ReadOnlySpan<byte> Address)
            {
                ushort Partition = BinaryPrimitives.ReadUInt16LittleEndian(Address.Slice(4));
                if (Partition != 0)
                    throw new NotSupportedException($"The UDF volume references partition {Partition}; only single partition media is supported.");

                return BinaryPrimitives.ReadUInt32LittleEndian(Address);
            }

            private readonly struct UdfExtent
            {
                public readonly uint Block;
                public readonly long LogicalOffset;
                public readonly long Length;

                public UdfExtent(uint Block, long LogicalOffset, long Length)
                {
                    this.Block = Block;
                    this.LogicalOffset = LogicalOffset;
                    this.Length = Length;
                }
            }

            private sealed class FileEntry
            {
                public long InformationLength;
                public long LogicalLength;
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

                    ulong InformationLength = BinaryPrimitives.ReadUInt64LittleEndian(Descriptor.Slice(56));
                    if (InformationLength > long.MaxValue)
                        throw new InvalidDataException($"The UDF file entry at block {Block} declares an information length of {InformationLength} bytes.");

                    FileEntry Entry = new FileEntry
                    {
                        InformationLength = (long)InformationLength,
                    };

                    uint ExtendedAttributeLength = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(Base - 8));
                    uint AllocationLength = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(Base - 4));

                    if ((ulong)Base + ExtendedAttributeLength + AllocationLength > (ulong)Descriptor.Length)
                        throw new InvalidDataException($"The UDF file entry at block {Block} declares {ExtendedAttributeLength} bytes of extended attributes and {AllocationLength} bytes of allocation descriptors that do not fit in one block.");

                    int AllocationOffset = Base + (int)ExtendedAttributeLength;

                    ReadOnlySpan<byte> Allocation = Descriptor.Slice(AllocationOffset, (int)AllocationLength);

                    if (DescriptorType == 3)
                    {
                        Entry.InlineData = Allocation.ToArray();
                        Entry.InformationLength = Math.Min(Entry.InformationLength, Allocation.Length);
                        return Entry;
                    }

                    if (ReadAllocationDescriptors(Allocation, DescriptorType, Entry, out uint NextBlock, out int NextLength))
                        ReadAllocationExtents(Source, NextBlock, NextLength, DescriptorType, Entry);

                    return Entry;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Buffer);
                }
            }

            /// <summary>
            /// Returns true when the sequence continues in the allocation extent at <paramref name="NextBlock"/>.
            /// </summary>
            private static bool ReadAllocationDescriptors(ReadOnlySpan<byte> Descriptors, int DescriptorType, FileEntry Entry, out uint NextBlock, out int NextLength)
            {
                NextBlock = 0;
                NextLength = 0;

                int Stride = DescriptorType switch
                {
                    0 => 8,
                    1 => 16,
                    2 => 20,
                    _ => throw new InvalidDataException($"Unknown UDF allocation descriptor type {DescriptorType}."),
                };
                int LocationOffset = DescriptorType == 2 ? 12 : 4;
                int Offset = 0;

                while (Offset + Stride <= Descriptors.Length)
                {
                    ReadOnlySpan<byte> Descriptor = Descriptors.Slice(Offset, Stride);
                    uint Raw = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor);

                    long Length = Raw & 0x3FFFFFFF;
                    int Type = (int)(Raw >> 30);

                    Offset += Stride;

                    if (Length == 0)
                        return false;

                    uint Block = 0;

                    if (Type == 0 || Type == 3)
                    {
                        Block = DescriptorType == 0
                            ? BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(4))
                            : ReadBlockAddress(Descriptor.Slice(LocationOffset));
                    }

                    if (Type == 3)
                    {
                        NextBlock = Block;
                        NextLength = (int)Length;
                        return true;
                    }

                    long InformationLength = Length;

                    // ECMA-167 4/14.14.3. Recorded Length below Information Length means encoded data.
                    if (DescriptorType == 2)
                    {
                        long RecordedLength = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(4)) & 0x3FFFFFFF;
                        InformationLength = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(8));

                        if (Type == 0 && RecordedLength < InformationLength)
                            throw new NotSupportedException($"The UDF extent at block {Block} records {RecordedLength} of {InformationLength} bytes; encoded extents are not supported.");
                    }

                    if (InformationLength == 0)
                        continue;

                    if (Type == 0)
                        Entry.Extents.Add(new UdfExtent(Block, Entry.LogicalLength, InformationLength));

                    Entry.LogicalLength += InformationLength;
                }

                return false;
            }

            private void ReadAllocationExtents(ImageDataSource Source, uint Block, int Length, int DescriptorType, FileEntry Entry)
            {
                HashSet<uint> Visited = new HashSet<uint>();
                byte[] Buffer = ArrayPool<byte>.Shared.Rent((int)BlockSize);

                try
                {
                    Span<byte> Descriptor = Buffer.AsSpan(0, (int)BlockSize);

                    while (true)
                    {
                        if (!Visited.Add(Block))
                            throw new InvalidDataException($"The UDF allocation extent chain returns to block {Block}.");

                        Source.ReadExact((long)(PartitionStart + Block) * BlockSize, Descriptor);

                        if (BinaryPrimitives.ReadUInt16LittleEndian(Descriptor) != TagAllocationExtentDescriptor)
                            throw new InvalidDataException($"Expected a UDF allocation extent descriptor at block {Block}.");

                        int Available = (int)BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(20));
                        if (Length - 24 < Available)
                            Available = Length - 24;

                        if ((uint)Available > (uint)(Descriptor.Length - 24))
                            throw new InvalidDataException($"The UDF allocation extent at block {Block} does not fit in one block.");

                        if (!ReadAllocationDescriptors(Descriptor.Slice(24, Available), DescriptorType, Entry, out Block, out Length))
                            return;
                    }
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
