using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;

namespace Brovan.Core.Helpers
{
    internal static class SimdStringHelpers
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int IndexOfZeroByte(ReadOnlySpan<byte> Buffer)
        {
            if (Buffer.IsEmpty)
                return -1;

            if (Avx2.IsSupported && Buffer.Length >= 32)
            {
                ref byte R = ref MemoryMarshal.GetReference(Buffer);
                nuint Length = (nuint)Buffer.Length;
                nuint Offset = 0;
                Vector256<byte> Zero = Vector256<byte>.Zero;

                while (Length - Offset >= 32)
                {
                    Vector256<byte> Chunk = Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref R, Offset));
                    Vector256<byte> Cmp = Avx2.CompareEqual(Chunk, Zero);
                    int Mask = Avx2.MoveMask(Cmp);
                    if (Mask != 0)
                        return (int)Offset + System.Numerics.BitOperations.TrailingZeroCount(Mask);

                    Offset += 32;
                }

                int Tail = (int)(Length - Offset);
                if (Tail > 0)
                {
                    ReadOnlySpan<byte> TailSpan = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref R, Offset), Tail);
                    for (int i = 0; i < TailSpan.Length; i++)
                    {
                        if (TailSpan[i] == 0)
                            return (int)Offset + i;
                    }
                }

                return -1;
            }

            ref byte Ref = ref MemoryMarshal.GetReference(Buffer);
            int Len = Buffer.Length;
            int Pos = 0;

            while (Pos + 8 <= Len)
            {
                ulong Word = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref Ref, Pos));
                if (((Word - 0x0101010101010101UL) & ~Word & 0x8080808080808080UL) != 0)
                    break;
                Pos += 8;
            }

            for (int i = Pos; i < Len; i++)
            {
                if (Unsafe.Add(ref Ref, i) == 0)
                    return i;
            }

            return -1;
        }

        /// <summary>
        /// Finds the index of the first UTF-16 NUL character (0x0000) in a little-endian byte buffer.
        /// </summary>
        /// <remarks>
        /// This must NOT call IndexOfZeroByte, because in UTF-16LE every ASCII char
        /// has a zero high byte. Instead we cast to ushort and scan for zero ushorts.
        /// </remarks>
        /// <returns>Returns the byte index (always even), or -1 if no NUL is found.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int IndexOfUtf16Nul(ReadOnlySpan<byte> Buffer)
        {
            if (Buffer.IsEmpty)
                return -1;

            int charCount = Buffer.Length >> 1;
            if (charCount == 0)
                return -1;

            ReadOnlySpan<ushort> Chars = MemoryMarshal.Cast<byte, ushort>(Buffer);

            if (Avx2.IsSupported && charCount >= 16)
            {
                ref ushort R = ref MemoryMarshal.GetReference(Chars);
                nuint Length = (nuint)charCount;
                nuint Offset = 0;
                Vector256<ushort> Zero = Vector256<ushort>.Zero;

                while (Length - Offset >= 16)
                {
                    Vector256<ushort> Chunk = Unsafe.ReadUnaligned<Vector256<ushort>>(ref Unsafe.As<ushort, byte>(ref Unsafe.Add(ref R, Offset)));
                    Vector256<ushort> Cmp = Avx2.CompareEqual(Chunk, Zero);
                    int Mask = Avx2.MoveMask(Cmp.AsByte());

                    // Each zero ushort produces a "11" bit pair in Mask. Find first such pair.
                    int Paired = Mask & (Mask >> 1) & 0x55555555;
                    if (Paired != 0)
                    {
                        int CharIdx = System.Numerics.BitOperations.TrailingZeroCount(Paired) >> 1;
                        return (int)(Offset + (uint)CharIdx) * 2;
                    }

                    Offset += 16;
                }

                int Tail = (int)(Length - Offset);
                if (Tail > 0)
                {
                    ReadOnlySpan<ushort> TailSpan = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref R, Offset), Tail);
                    for (int i = 0; i < TailSpan.Length; i++)
                    {
                        if (TailSpan[i] == 0)
                            return ((int)Offset + i) * 2;
                    }
                }

                return -1;
            }

            // Scalar fallback
            for (int i = 0; i < charCount; i++)
            {
                if (Chars[i] == 0)
                    return i * 2;
            }

            return -1;
        }

        public static string TryDecodeAsciiAsUtf16(ReadOnlySpan<byte> Bytes)
        {
            if (Bytes.IsEmpty)
                return string.Empty;

            if (!IsPureAscii(Bytes))
                return null;

            char[] Rented = ArrayPool<char>.Shared.Rent(Bytes.Length);
            try
            {
                Span<char> Chars = Rented.AsSpan(0, Bytes.Length);
                WidenAsciiToUtf16(Bytes, Chars);
                return new string(Chars);
            }
            finally
            {
                ArrayPool<char>.Shared.Return(Rented);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsPureAscii(ReadOnlySpan<byte> Bytes)
        {
            if (Bytes.IsEmpty)
                return true;

            ref byte R = ref MemoryMarshal.GetReference(Bytes);
            nuint Length = (nuint)Bytes.Length;

            if (Avx2.IsSupported && Length >= 32)
            {
                Vector256<byte> HighBit = Vector256.Create((byte)0x80);
                nuint Offset = 0;
                while (Length - Offset >= 32)
                {
                    Vector256<byte> Chunk = Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref R, Offset));
                    Vector256<byte> Test = Avx2.And(Chunk, HighBit);
                    if (Test != Vector256<byte>.Zero)
                        return false;
                    Offset += 32;
                }

                int Tail = (int)(Length - Offset);
                if (Tail > 0)
                {
                    ReadOnlySpan<byte> TailSpan = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref R, Offset), Tail);
                    foreach (byte B in TailSpan)
                    {
                        if ((B & 0x80) != 0)
                            return false;
                    }
                }

                return true;
            }

            if (Sse2.IsSupported && Length >= 16)
            {
                Vector128<byte> HighBit = Vector128.Create((byte)0x80);
                nuint Offset = 0;
                while (Length - Offset >= 16)
                {
                    Vector128<byte> Chunk = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref R, Offset));
                    Vector128<byte> Test = Sse2.And(Chunk, HighBit);
                    if (Test != Vector128<byte>.Zero)
                        return false;
                    Offset += 16;
                }

                int Tail = (int)(Length - Offset);
                if (Tail > 0)
                {
                    ReadOnlySpan<byte> TailSpan = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref R, Offset), Tail);
                    foreach (byte B in TailSpan)
                    {
                        if ((B & 0x80) != 0)
                            return false;
                    }
                }

                return true;
            }

            nuint P = 0;
            while (Length - P >= 8)
            {
                ulong Word = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref R, P));
                if ((Word & 0x8080808080808080UL) != 0)
                    return false;
                P += 8;
            }

            for (nuint i = P; i < Length; i++)
            {
                if ((Unsafe.Add(ref R, i) & 0x80) != 0)
                    return false;
            }

            return true;
        }

        public static string TryDecodeUtf16LeString(ReadOnlySpan<byte> Bytes)
        {
            if (Bytes.IsEmpty)
                return string.Empty;

            if ((Bytes.Length & 1) != 0)
                return null;

            ReadOnlySpan<char> Chars = MemoryMarshal.Cast<byte, char>(Bytes);
            return new string(Chars);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsPureAsciiUtf16Le(ReadOnlySpan<byte> Bytes)
        {
            if (Bytes.IsEmpty || (Bytes.Length & 1) != 0)
                return false;

            ref byte R = ref MemoryMarshal.GetReference(Bytes);
            nuint Length = (nuint)Bytes.Length;

            if (Avx2.IsSupported && Length >= 32)
            {
                const int OddBits = unchecked((int)0xAAAAAAAAu);
                Vector256<byte> Zero = Vector256<byte>.Zero;
                Vector256<byte> HighBit = Vector256.Create((byte)0x80);
                nuint Offset = 0;

                while (Length - Offset >= 32)
                {
                    Vector256<byte> Chunk = Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.Add(ref R, Offset));
                    Vector256<byte> ZeroMask = Avx2.CompareEqual(Chunk, Zero);
                    int Mask = Avx2.MoveMask(ZeroMask);
                    if ((Mask & OddBits) != OddBits)
                        return false;

                    Vector256<byte> HiMask = Avx2.And(Chunk, HighBit);
                    int HiMoveMask = Avx2.MoveMask(HiMask);
                    if ((HiMoveMask & ~OddBits) != 0)
                        return false;

                    Offset += 32;
                }

                int Tail = (int)(Length - Offset);
                if (Tail > 0)
                {
                    ReadOnlySpan<byte> TailSpan = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref R, Offset), Tail);
                    for (int i = 0; i + 1 < TailSpan.Length; i += 2)
                    {
                        if (TailSpan[i + 1] != 0 || (TailSpan[i] & 0x80) != 0)
                            return false;
                    }
                }

                return true;
            }

            const ulong AsciiTest = 0x8080808080808080UL;
            nuint P = 0;
            while (Length - P >= 8)
            {
                ulong Word = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref R, P));
                if ((Word & AsciiTest) != 0)
                    return false;
                P += 8;
            }

            for (nuint i = P; i + 1 < Length; i += 2)
            {
                byte Lo = Unsafe.Add(ref R, i);
                byte Hi = Unsafe.Add(ref R, i + 1);
                if (Hi != 0 || (Lo & 0x80) != 0)
                    return false;
            }

            return true;
        }

        private static void WidenAsciiToUtf16(ReadOnlySpan<byte> Src, Span<char> Dst)
        {
            System.Diagnostics.Debug.Assert(Src.Length == Dst.Length);
            if (Src.IsEmpty)
                return;

            ref byte S = ref MemoryMarshal.GetReference(Src);
            ref char D = ref MemoryMarshal.GetReference(Dst);
            nuint Length = (nuint)Src.Length;

            if (Sse2.IsSupported)
            {
                Vector128<byte> Zero = Vector128<byte>.Zero;
                nuint Offset = 0;
                while (Length - Offset >= 16)
                {
                    Vector128<byte> Chunk = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref S, Offset));
                    Vector128<byte> Lo = Sse2.UnpackLow(Chunk, Zero);
                    Vector128<byte> Hi = Sse2.UnpackHigh(Chunk, Zero);
                    Unsafe.WriteUnaligned(ref Unsafe.As<char, byte>(ref Unsafe.Add(ref D, Offset)), Lo);
                    Unsafe.WriteUnaligned(ref Unsafe.As<char, byte>(ref Unsafe.Add(ref D, Offset + 8)), Hi);
                    Offset += 16;
                }

                int Tail = (int)(Length - Offset);
                if (Tail > 0)
                {
                    ReadOnlySpan<byte> SrcTail = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref S, Offset), Tail);
                    Span<char> DstTail = MemoryMarshal.CreateSpan(ref Unsafe.Add(ref D, Offset), Tail);
                    for (int i = 0; i < SrcTail.Length; i++)
                        DstTail[i] = (char)SrcTail[i];
                }

                return;
            }

            for (nuint i = 0; i < Length; i++)
                Unsafe.Add(ref D, i) = (char)Unsafe.Add(ref S, i);
        }
    }
}
