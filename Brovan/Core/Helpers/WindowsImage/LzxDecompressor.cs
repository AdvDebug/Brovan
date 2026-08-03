using System;
using System.Buffers.Binary;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal sealed class LzxDecompressor
    {
        private const int MinMatchLength = 2;
        private const int NumLengthSymbols = 249;
        private const int NumPretreeSymbols = 20;
        private const int NumAlignedSymbols = 8;
        private const int OffsetAdjustment = 2;
        private const int DefaultBlockSize = 32768;
        private const int MagicFileSize = 12000000;

        private const int BlockTypeVerbatim = 1;
        private const int BlockTypeAligned = 2;
        private const int BlockTypeUncompressed = 3;

        private static readonly byte[] ExtraBits = BuildExtraBits();
        private static readonly uint[] PositionBase = BuildPositionBase();

        private readonly int WindowOrder;
        private readonly int PositionSlots;
        private readonly int MainSymbols;

        private readonly byte[] MainLengths;
        private readonly byte[] LengthLengths = new byte[NumLengthSymbols];
        private readonly byte[] AlignedLengths = new byte[NumAlignedSymbols];
        private readonly byte[] PretreeLengths = new byte[NumPretreeSymbols];

        private readonly HuffmanDecodeTable MainTable;
        private readonly HuffmanDecodeTable LengthTable = new HuffmanDecodeTable(NumLengthSymbols, 10);
        private readonly HuffmanDecodeTable AlignedTable = new HuffmanDecodeTable(NumAlignedSymbols, 7);
        private readonly HuffmanDecodeTable PretreeTable = new HuffmanDecodeTable(NumPretreeSymbols, 6);

        public LzxDecompressor(int ChunkSize)
        {
            WindowOrder = 15;
            while ((1 << WindowOrder) < ChunkSize)
                WindowOrder++;

            PositionSlots = SlotsForWindowOrder(WindowOrder);
            MainSymbols = 256 + (PositionSlots * 8);
            MainLengths = new byte[MainSymbols];
            MainTable = new HuffmanDecodeTable(MainSymbols, 11);
        }

        private static int SlotsForWindowOrder(int Order)
        {
            return Order switch
            {
                15 => 30,
                16 => 32,
                17 => 34,
                18 => 36,
                19 => 38,
                20 => 42,
                _ => 50,
            };
        }

        private static byte[] BuildExtraBits()
        {
            byte[] Bits = new byte[51];

            for (int Slot = 0; Slot < Bits.Length; Slot++)
            {
                if (Slot < 4)
                    Bits[Slot] = 0;
                else if (Slot < 36)
                    Bits[Slot] = (byte)((Slot / 2) - 1);
                else
                    Bits[Slot] = 17;
            }

            return Bits;
        }

        private static uint[] BuildPositionBase()
        {
            byte[] Bits = BuildExtraBits();
            uint[] Base = new uint[Bits.Length];
            uint Value = 0;

            for (int Slot = 0; Slot < Bits.Length; Slot++)
            {
                Base[Slot] = Value;
                Value += 1u << Bits[Slot];
            }

            return Base;
        }

        public bool Decompress(ReadOnlySpan<byte> Input, Span<byte> Output)
        {
            Array.Clear(MainLengths);
            Array.Clear(LengthLengths);

            WimBitStream Stream = new WimBitStream(Input);

            uint Recent0 = 1;
            uint Recent1 = 1;
            uint Recent2 = 1;

            int Position = 0;
            bool MayHaveTranslation = false;

            while (Position < Output.Length)
            {
                int BlockType = (int)Stream.ReadBits(3);
                int BlockSize;

                if (Stream.ReadBits(1) != 0)
                {
                    BlockSize = DefaultBlockSize;
                }
                else
                {
                    BlockSize = (int)Stream.ReadBits(16);

                    if (WindowOrder >= 16)
                        BlockSize = (BlockSize << 8) | (int)Stream.ReadBits(8);
                }

                if (BlockSize <= 0 || Position + BlockSize > Output.Length)
                    return false;

                if (BlockType == BlockTypeUncompressed)
                {
                    if (!ReadUncompressedBlock(ref Stream, Output.Slice(Position, BlockSize), ref Recent0, ref Recent1, ref Recent2))
                        return false;

                    Position += BlockSize;
                    MayHaveTranslation = true;
                    continue;
                }

                if (BlockType != BlockTypeVerbatim && BlockType != BlockTypeAligned)
                    return false;

                if (BlockType == BlockTypeAligned)
                {
                    for (int i = 0; i < NumAlignedSymbols; i++)
                        AlignedLengths[i] = (byte)Stream.ReadBits(3);

                    if (!AlignedTable.Build(AlignedLengths))
                        return false;
                }

                if (!ReadLengths(ref Stream, MainLengths, 0, 256) ||
                    !ReadLengths(ref Stream, MainLengths, 256, MainSymbols - 256) ||
                    !MainTable.Build(MainLengths))
                    return false;

                if (!ReadLengths(ref Stream, LengthLengths, 0, NumLengthSymbols) ||
                    !LengthTable.Build(LengthLengths))
                    return false;

                int End = Position + BlockSize;
                bool Aligned = BlockType == BlockTypeAligned;

                while (Position < End)
                {
                    int Symbol = MainTable.Decode(ref Stream);
                    if (Symbol < 0)
                        return false;

                    if (Symbol < 256)
                    {
                        Output[Position++] = (byte)Symbol;
                        MayHaveTranslation |= Symbol == 0xE8;
                        continue;
                    }

                    Symbol -= 256;

                    int LengthHeader = Symbol & 7;
                    int Slot = Symbol >> 3;

                    if (Slot >= PositionSlots)
                        return false;

                    int Length;

                    if (LengthHeader == 7)
                    {
                        int Extra = LengthTable.Decode(ref Stream);
                        if (Extra < 0)
                            return false;

                        Length = Extra + 7 + MinMatchLength;
                    }
                    else
                    {
                        Length = LengthHeader + MinMatchLength;
                    }

                    uint Offset;

                    if (Slot == 0)
                    {
                        Offset = Recent0;
                    }
                    else if (Slot == 1)
                    {
                        Offset = Recent1;
                        Recent1 = Recent0;
                        Recent0 = Offset;
                    }
                    else if (Slot == 2)
                    {
                        Offset = Recent2;
                        Recent2 = Recent0;
                        Recent0 = Offset;
                    }
                    else
                    {
                        int Bits = ExtraBits[Slot];
                        uint Value;

                        if (Aligned && Bits >= 3)
                        {
                            uint Verbatim = Stream.ReadBits(Bits - 3);
                            int AlignedSymbol = AlignedTable.Decode(ref Stream);
                            if (AlignedSymbol < 0)
                                return false;

                            Value = (Verbatim << 3) | (uint)AlignedSymbol;
                        }
                        else
                        {
                            Value = Stream.ReadBits(Bits);
                        }

                        Offset = PositionBase[Slot] + Value - OffsetAdjustment;
                        Recent2 = Recent1;
                        Recent1 = Recent0;
                        Recent0 = Offset;
                    }

                    if (Offset == 0 || Offset > (uint)Position || Position + Length > End)
                        return false;

                    LzOutput.CopyMatch(Output, Position, (int)Offset, Length);
                    Position += Length;
                }
            }

            if (MayHaveTranslation)
                UndoTranslation(Output);

            return true;
        }

        private bool ReadUncompressedBlock(ref WimBitStream Stream, Span<byte> Output, ref uint Recent0, ref uint Recent1, ref uint Recent2)
        {
            Stream.AlignToWord();

            Span<byte> Offsets = stackalloc byte[12];
            if (!Stream.TryReadRaw(Offsets))
                return false;

            Recent0 = BinaryPrimitives.ReadUInt32LittleEndian(Offsets);
            Recent1 = BinaryPrimitives.ReadUInt32LittleEndian(Offsets.Slice(4));
            Recent2 = BinaryPrimitives.ReadUInt32LittleEndian(Offsets.Slice(8));

            if (Recent0 == 0 || Recent1 == 0 || Recent2 == 0)
                return false;

            if (!Stream.TryCopyRaw(Output, Output.Length))
                return false;

            if ((Output.Length & 1) != 0)
                Stream.SkipToEvenPosition();

            return true;
        }

        private bool ReadLengths(ref WimBitStream Stream, byte[] Lengths, int Start, int Count)
        {
            for (int i = 0; i < NumPretreeSymbols; i++)
                PretreeLengths[i] = (byte)Stream.ReadBits(4);

            if (!PretreeTable.Build(PretreeLengths))
                return false;

            int Index = Start;
            int End = Start + Count;

            while (Index < End)
            {
                int Symbol = PretreeTable.Decode(ref Stream);
                if (Symbol < 0)
                    return false;

                if (Symbol == 17)
                {
                    int Run = (int)Stream.ReadBits(4) + 4;

                    while (Run-- > 0 && Index < End)
                        Lengths[Index++] = 0;
                }
                else if (Symbol == 18)
                {
                    int Run = (int)Stream.ReadBits(5) + 20;

                    while (Run-- > 0 && Index < End)
                        Lengths[Index++] = 0;
                }
                else if (Symbol == 19)
                {
                    int Run = (int)Stream.ReadBits(1) + 4;

                    int Delta = PretreeTable.Decode(ref Stream);
                    if (Delta < 0 || Delta > 16)
                        return false;

                    byte Value = (byte)((Lengths[Index] - Delta + 17) % 17);

                    while (Run-- > 0 && Index < End)
                        Lengths[Index++] = Value;
                }
                else
                {
                    Lengths[Index] = (byte)((Lengths[Index] - Symbol + 17) % 17);
                    Index++;
                }
            }

            return true;
        }

        private static void UndoTranslation(Span<byte> Output)
        {
            if (Output.Length <= 10)
                return;

            int Limit = Output.Length - 10;
            int i = 0;

            while (i < Limit)
            {
                if (Output[i] != 0xE8)
                {
                    i++;
                    continue;
                }

                int Absolute = BinaryPrimitives.ReadInt32LittleEndian(Output.Slice(i + 1));

                if (Absolute >= -i && Absolute < MagicFileSize)
                {
                    int Relative = Absolute >= 0 ? Absolute - i : Absolute + MagicFileSize;
                    BinaryPrimitives.WriteInt32LittleEndian(Output.Slice(i + 1), Relative);
                }

                i += 5;
            }
        }
    }
}
