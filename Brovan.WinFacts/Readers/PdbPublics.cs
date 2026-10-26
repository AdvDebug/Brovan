using System.Buffers.Binary;
using System.Text;
using Brovan.WinFacts.Sources;

namespace Brovan.WinFacts.Readers
{
    // Reads S_PUB32 records from MSF 7.00 PDBs only.
    internal sealed class PdbPublics
    {
        private static readonly byte[] MsfMagic = Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0");
        private const int DbiStream = 3;
        private const int DbiSymRecordStreamOffset = 20;
        private const ushort SymbolPub32 = 0x110E;
        private const uint NilStream = 0xFFFFFFFF;

        private readonly Dictionary<string, uint> ByName = new(StringComparer.Ordinal);
        private readonly List<(uint Rva, string Name)> ByRva = new();

        internal int Count => ByName.Count;

        internal static PdbPublics Open(IByteSource Source, PeImage Image)
        {
            byte[] Super = new byte[56];
            if (!Source.TryRead(0, Super) || !Super.AsSpan(0, MsfMagic.Length).SequenceEqual(MsfMagic))
                throw new InvalidDataException("not an MSF 7.00 PDB");

            uint BlockSize = BinaryPrimitives.ReadUInt32LittleEndian(Super.AsSpan(32));
            uint DirectoryBytes = BinaryPrimitives.ReadUInt32LittleEndian(Super.AsSpan(44));
            uint BlockMapAddress = BinaryPrimitives.ReadUInt32LittleEndian(Super.AsSpan(52));
            if (BlockSize is not (512 or 1024 or 2048 or 4096) || DirectoryBytes > 0x1000000)
                throw new InvalidDataException("bad MSF superblock");

            uint DirectoryBlocks = (DirectoryBytes + BlockSize - 1) / BlockSize;
            byte[] BlockMap = ReadBytes(Source, (long)BlockMapAddress * BlockSize, (int)(DirectoryBlocks * 4));
            byte[] Directory = ReadBlocks(Source, BlockSize, BlockMap, DirectoryBlocks, (int)DirectoryBytes);

            uint StreamCount = Directory.Length < 4 ? uint.MaxValue : BinaryPrimitives.ReadUInt32LittleEndian(Directory);
            if (StreamCount > (uint)(Directory.Length - 4) / 4)
                throw new InvalidDataException("bad MSF stream directory");

            uint[] Sizes = new uint[StreamCount];
            int Cursor = 4;
            for (int i = 0; i < StreamCount; i++, Cursor += 4)
            {
                uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Directory.AsSpan(Cursor));
                Sizes[i] = Size == NilStream ? 0 : Size;
                if (Sizes[i] > int.MaxValue)
                    throw new InvalidDataException("bad MSF stream size");
            }

            int[] FirstBlockEntry = new int[StreamCount];
            long BlockListEnd = Cursor;
            for (int i = 0; i < StreamCount; i++)
            {
                FirstBlockEntry[i] = (int)Math.Min(BlockListEnd, int.MaxValue);
                BlockListEnd += (Sizes[i] + BlockSize - 1) / BlockSize * 4;
            }

            if (BlockListEnd > Directory.Length)
                throw new InvalidDataException("bad MSF stream directory");

            byte[] ReadStream(int Index, uint Limit = uint.MaxValue)
            {
                if ((uint)Index >= StreamCount)
                    throw new InvalidDataException($"no PDB stream {Index}");

                uint Size = Math.Min(Sizes[Index], Limit);
                uint Blocks = (Size + BlockSize - 1) / BlockSize;
                return ReadBlocks(Source, BlockSize, Directory.AsSpan(FirstBlockEntry[Index], (int)Blocks * 4), Blocks, (int)Size);
            }

            byte[] Dbi = ReadStream(DbiStream, DbiSymRecordStreamOffset + sizeof(ushort));
            if (Dbi.Length < DbiSymRecordStreamOffset + sizeof(ushort))
                throw new InvalidDataException("short DBI stream");

            int SymRecords = BinaryPrimitives.ReadUInt16LittleEndian(Dbi.AsSpan(DbiSymRecordStreamOffset));
            byte[] Records = ReadStream(SymRecords);

            PdbPublics Publics = new();
            for (int Offset = 0; Offset + 4 <= Records.Length;)
            {
                int Length = BinaryPrimitives.ReadUInt16LittleEndian(Records.AsSpan(Offset));
                ushort Kind = BinaryPrimitives.ReadUInt16LittleEndian(Records.AsSpan(Offset + 2));
                if (Length < 2 || Offset + 2 + Length > Records.Length)
                    break;

                if (Kind == SymbolPub32 && Length >= 12)
                {
                    uint SymbolOffset = BinaryPrimitives.ReadUInt32LittleEndian(Records.AsSpan(Offset + 8));
                    int Segment = BinaryPrimitives.ReadUInt16LittleEndian(Records.AsSpan(Offset + 12));
                    int NameStart = Offset + 14;
                    int NameEnd = Array.IndexOf(Records, (byte)0, NameStart, Offset + 2 + Length - NameStart);
                    if (Segment >= 1 && Segment <= Image.Sections.Count && NameEnd > NameStart)
                    {
                        string Name = Encoding.UTF8.GetString(Records, NameStart, NameEnd - NameStart);
                        uint Rva = Image.Sections[Segment - 1].VirtualAddress + SymbolOffset;
                        Publics.ByName.TryAdd(Name, Rva);
                        Publics.ByRva.Add((Rva, Name));
                    }
                }

                Offset += 2 + Length;
            }

            Publics.ByRva.Sort((A, B) => A.Rva != B.Rva ? A.Rva.CompareTo(B.Rva) : string.CompareOrdinal(A.Name, B.Name));
            return Publics;
        }

        internal bool TryGet(string Name, out uint Rva) => ByName.TryGetValue(Name, out Rva);

        // Fails unless exactly one decorated name has this prefix and suffix.
        internal uint Find(string Prefix, string Suffix = "")
        {
            int Matches = CountMatches(Prefix, Suffix, out uint Rva);
            return Matches == 1 ? Rva : throw new FactException($"symbol {Prefix}*{Suffix}: {Matches} matches");
        }

        internal bool TryFind(string Prefix, string Suffix, out uint Rva) => CountMatches(Prefix, Suffix, out Rva) == 1;

        private int CountMatches(string Prefix, string Suffix, out uint Rva)
        {
            Rva = 0;
            int Matches = 0;
            foreach ((string Name, uint Each) in ByName)
            {
                if (!Name.StartsWith(Prefix, StringComparison.Ordinal) || !Name.EndsWith(Suffix, StringComparison.Ordinal))
                    continue;

                Matches++;
                Rva = Each;
            }

            return Matches;
        }

        internal IEnumerable<(string Name, uint Rva)> NamesStartingWith(string Prefix)
        {
            foreach ((string Name, uint Rva) in ByName)
            {
                if (Name.StartsWith(Prefix, StringComparison.Ordinal))
                    yield return (Name, Rva);
            }
        }

        // The lowest name wins when several symbols share the RVA.
        internal string NameAt(uint Rva)
        {
            int Index = LowerBound(Rva);
            return Index < ByRva.Count && ByRva[Index].Rva == Rva ? ByRva[Index].Name : null;
        }

        // Identical functions folded by the linker share one RVA.
        internal IEnumerable<string> NamesAt(uint Rva)
        {
            for (int Index = LowerBound(Rva); Index < ByRva.Count && ByRva[Index].Rva == Rva; Index++)
                yield return ByRva[Index].Name;
        }

        internal uint NextAfter(uint Rva)
        {
            int Index = LowerBound(Rva + 1);
            return Index < ByRva.Count ? ByRva[Index].Rva : uint.MaxValue;
        }

        private int LowerBound(uint Rva)
        {
            int Low = 0, High = ByRva.Count;
            while (Low < High)
            {
                int Middle = (Low + High) / 2;
                if (ByRva[Middle].Rva < Rva)
                    Low = Middle + 1;
                else
                    High = Middle;
            }

            return Low;
        }

        private static byte[] ReadBytes(IByteSource Source, long Offset, int Count)
        {
            byte[] Bytes = new byte[Count];
            if (!Source.TryRead(Offset, Bytes))
                throw new InvalidDataException("truncated PDB");

            return Bytes;
        }

        private static byte[] ReadBlocks(IByteSource Source, uint BlockSize, ReadOnlySpan<byte> BlockList, uint Blocks, int Size)
        {
            byte[] Bytes = new byte[Size];
            for (int i = 0; i < Blocks; i++)
            {
                uint Block = BinaryPrimitives.ReadUInt32LittleEndian(BlockList.Slice(i * 4));
                int Count = (int)Math.Min(BlockSize, (uint)(Size - i * BlockSize));
                if (!Source.TryRead((long)Block * BlockSize, Bytes.AsSpan((int)(i * BlockSize), Count)))
                    throw new InvalidDataException("truncated PDB stream");
            }

            return Bytes;
        }
    }
}
