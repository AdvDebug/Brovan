using System;
using System.Runtime.CompilerServices;

namespace Brovan.Core.Helpers.WindowsImage
{
    internal ref struct WimBitStream
    {
        private readonly ReadOnlySpan<byte> Data;
        private int Position;
        private uint Buffer;
        private int Count;

        public WimBitStream(ReadOnlySpan<byte> Data)
        {
            this.Data = Data;
            Position = 0;
            Buffer = 0;
            Count = 0;
        }

        public readonly int BitPosition => (Position * 8) - Count;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Ensure(int Bits)
        {
            while (Count < Bits)
            {
                uint Word;

                if (Position + 1 < Data.Length)
                    Word = (uint)(Data[Position] | (Data[Position + 1] << 8));
                else if (Position < Data.Length)
                    Word = Data[Position];
                else
                    Word = 0;

                Position += 2;
                Buffer = ((Buffer & ((1u << Count) - 1)) << 16) | Word;
                Count += 16;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public readonly uint Peek(int Bits)
        {
            return Bits == 0 ? 0 : (Buffer >> (Count - Bits)) & ((1u << Bits) - 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Remove(int Bits)
        {
            Count -= Bits;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public uint ReadBits(int Bits)
        {
            if (Bits == 0)
                return 0;

            if (Bits <= 16)
            {
                Ensure(Bits);
                uint Value = Peek(Bits);
                Remove(Bits);
                return Value;
            }

            uint High = ReadBits(Bits - 16);
            return (High << 16) | ReadBits(16);
        }

        /// <summary>
        /// Discards the remainder of the current 16 bit word, which is how LZX introduces an uncompressed block.
        /// </summary>
        public void AlignToWord()
        {
            int Bits = BitPosition;
            Position = ((Bits + 15) / 16) * 2;
            Buffer = 0;
            Count = 0;
        }

        public int ReadRawByte()
        {
            if (Position >= Data.Length)
                return -1;

            return Data[Position++];
        }

        public int ReadRawUInt16()
        {
            if (Position + 1 >= Data.Length)
                return -1;

            int Value = Data[Position] | (Data[Position + 1] << 8);
            Position += 2;
            return Value;
        }

        public bool TryReadRaw(scoped Span<byte> Destination)
        {
            if (Count != 0)
                throw new InvalidOperationException("Raw reads require an aligned bit stream.");

            if (Position + Destination.Length > Data.Length)
                return false;

            Data.Slice(Position, Destination.Length).CopyTo(Destination);
            Position += Destination.Length;
            return true;
        }

        public bool TryCopyRaw(scoped Span<byte> Destination, int Length)
        {
            if (Count != 0)
                throw new InvalidOperationException("Raw reads require an aligned bit stream.");

            if (Position + Length > Data.Length || Length > Destination.Length)
                return false;

            Data.Slice(Position, Length).CopyTo(Destination);
            Position += Length;
            return true;
        }

        public void SkipToEvenPosition()
        {
            if ((Position & 1) != 0)
                Position++;
        }
    }

    internal static class LzOutput
    {
        public static void CopyMatch(Span<byte> Output, int Position, int Offset, int Length)
        {
            int Source = Position - Offset;

            if (Offset >= Length)
            {
                Output.Slice(Source, Length).CopyTo(Output.Slice(Position, Length));
                return;
            }

            for (int i = 0; i < Length; i++)
                Output[Position + i] = Output[Source + i];
        }
    }

    internal sealed class HuffmanDecodeTable
    {
        private const int MaxCodeLength = 16;
        private const ushort EmptyEntry = 0xFFFF;

        private readonly ushort[] Table;
        private readonly ushort[] SortedSymbols;
        private readonly int[] LengthCounts = new int[MaxCodeLength + 1];
        private readonly int[] FirstCode = new int[MaxCodeLength + 1];
        private readonly int[] FirstIndex = new int[MaxCodeLength + 1];
        private readonly int TableBits;
        private int LongestLength;

        public HuffmanDecodeTable(int SymbolCount, int TableBits)
        {
            this.TableBits = TableBits;
            Table = new ushort[1 << TableBits];
            SortedSymbols = new ushort[SymbolCount];
        }

        public bool Build(ReadOnlySpan<byte> Lengths)
        {
            Array.Clear(LengthCounts);

            for (int Symbol = 0; Symbol < Lengths.Length; Symbol++)
            {
                int Length = Lengths[Symbol];
                if (Length > MaxCodeLength)
                    return false;

                LengthCounts[Length]++;
            }

            int Code = 0;
            int Index = 0;
            LongestLength = 0;

            for (int Length = 1; Length <= MaxCodeLength; Length++)
            {
                FirstCode[Length] = Code;
                FirstIndex[Length] = Index;

                int Used = LengthCounts[Length];
                if (Used != 0)
                    LongestLength = Length;

                if (Code + Used > (1 << Length))
                    return false;

                Index += Used;
                Code = (Code + Used) << 1;
            }

            Span<int> Next = stackalloc int[MaxCodeLength + 1];
            for (int Length = 1; Length <= MaxCodeLength; Length++)
                Next[Length] = FirstIndex[Length];

            for (int Symbol = 0; Symbol < Lengths.Length; Symbol++)
            {
                int Length = Lengths[Symbol];
                if (Length != 0)
                    SortedSymbols[Next[Length]++] = (ushort)Symbol;
            }

            Table.AsSpan().Fill(EmptyEntry);

            int Limit = Math.Min(TableBits, LongestLength);

            for (int Length = 1; Length <= Limit; Length++)
            {
                int Used = LengthCounts[Length];
                int Shift = TableBits - Length;
                int Run = 1 << Shift;

                for (int i = 0; i < Used; i++)
                {
                    ushort Symbol = SortedSymbols[FirstIndex[Length] + i];
                    int Start = (FirstCode[Length] + i) << Shift;
                    Table.AsSpan(Start, Run).Fill((ushort)((Symbol << 5) | Length));
                }
            }

            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int Decode(ref WimBitStream Stream)
        {
            Stream.Ensure(MaxCodeLength);

            ushort Entry = Table[Stream.Peek(TableBits)];

            if (Entry != EmptyEntry)
            {
                Stream.Remove(Entry & 31);
                return Entry >> 5;
            }

            for (int Length = TableBits + 1; Length <= LongestLength; Length++)
            {
                int Used = LengthCounts[Length];
                if (Used == 0)
                    continue;

                int Offset = (int)Stream.Peek(Length) - FirstCode[Length];
                if (Offset >= 0 && Offset < Used)
                {
                    Stream.Remove(Length);
                    return SortedSymbols[FirstIndex[Length] + Offset];
                }
            }

            return -1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int Decode(ref LzmsDecompressor.LzmsBitStream Stream)
        {
            Stream.Ensure(MaxCodeLength);

            ushort Entry = Table[Stream.Peek(TableBits)];

            if (Entry != EmptyEntry)
            {
                Stream.Remove(Entry & 31);
                return Entry >> 5;
            }

            for (int Length = TableBits + 1; Length <= LongestLength; Length++)
            {
                int Used = LengthCounts[Length];
                if (Used == 0)
                    continue;

                int Offset = (int)Stream.Peek(Length) - FirstCode[Length];
                if (Offset >= 0 && Offset < Used)
                {
                    Stream.Remove(Length);
                    return SortedSymbols[FirstIndex[Length] + Offset];
                }
            }

            return -1;
        }
    }
}
