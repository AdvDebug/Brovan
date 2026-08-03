using System;

namespace Brovan.Core.Helpers.WindowsImage
{
    /// <summary>
    /// XPRESS Huffman chunk decoder, the format WIM uses for its fastest compression level and the same one
    /// </summary>
    internal sealed class XpressDecompressor
    {
        private const int SymbolCount = 512;
        private const int TableBytes = SymbolCount / 2;
        private const int TableBits = 10;

        private readonly HuffmanDecodeTable Table = new HuffmanDecodeTable(SymbolCount, TableBits);
        private readonly byte[] Lengths = new byte[SymbolCount];

        public bool Decompress(ReadOnlySpan<byte> Input, Span<byte> Output)
        {
            if (Input.Length < TableBytes)
                return false;

            for (int i = 0; i < TableBytes; i++)
            {
                Lengths[i * 2] = (byte)(Input[i] & 0x0F);
                Lengths[(i * 2) + 1] = (byte)(Input[i] >> 4);
            }

            if (!Table.Build(Lengths))
                return false;

            WimBitStream Stream = new WimBitStream(Input.Slice(TableBytes));

            Stream.Ensure(32);

            int Position = 0;

            while (Position < Output.Length)
            {
                int Symbol = Table.Decode(ref Stream);
                if (Symbol < 0)
                    return false;

                Stream.Ensure(16);

                if (Symbol < 256)
                {
                    Output[Position++] = (byte)Symbol;
                    continue;
                }

                Symbol -= 256;

                int Length = Symbol & 0x0F;
                int OffsetBits = Symbol >> 4;

                if (Length == 15)
                {
                    Length = Stream.ReadRawByte();
                    if (Length < 0)
                        return false;

                    if (Length == 255)
                    {
                        Length = Stream.ReadRawUInt16();
                        if (Length < 15)
                            return false;

                        Length -= 15;
                    }

                    Length += 15;
                }

                Length += 3;

                int Offset = (int)Stream.ReadBits(OffsetBits) + (1 << OffsetBits);
                Stream.Ensure(16);

                if (Offset > Position || Position + Length > Output.Length)
                    return false;

                LzOutput.CopyMatch(Output, Position, Offset, Length);
                Position += Length;
            }

            return true;
        }
    }
}
