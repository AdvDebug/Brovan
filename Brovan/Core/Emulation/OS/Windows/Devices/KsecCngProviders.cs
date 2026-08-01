using System;
using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class KsecCngProviders
    {
        internal const uint RequestMagic = 0x1A2B3C4D;
        internal const uint RequestResolveProviders = 0x00020000;

        private const string PrimitiveProvider = "Microsoft Primitive Provider";
        private const string PrimitiveImage = "bcryptprimitives.dll";
        private const uint ImageFlagsUserMode = 1;
        private const int NullReference = -1;
        private const uint CryptUserMode = 1;
        private const uint CryptModeMask = 3;

        private const int InterfaceOffset = 0x10;
        private const int FunctionOffset = 0x18;
        private const int ProviderOffset = 0x20;
        private const int ModeOffset = 0x28;
        private const int HeaderSize = 0x30;

        private static readonly (string Name, uint Interface)[] Algorithms =
        {
            ("3DES", 1), ("3DES_112", 1), ("AES", 1), ("DES", 1), ("DESX", 1), ("RC2", 1), ("RC4", 1),
            ("AES-CMAC", 2), ("AES-GMAC", 2), ("MD2", 2), ("MD4", 2), ("MD5", 2),
            ("SHA1", 2), ("SHA256", 2), ("SHA384", 2), ("SHA512", 2),
            ("RSA", 3),
            ("DH", 4), ("ECDH", 4), ("ECDH_P256", 4), ("ECDH_P384", 4), ("ECDH_P521", 4),
            ("DSA", 5), ("ECDSA", 5), ("ECDSA_P256", 5), ("ECDSA_P384", 5), ("ECDSA_P521", 5), ("RSA_SIGN", 5),
            ("RNG", 6),
            ("CAPI_KDF", 7), ("PBKDF2", 7), ("SP800_108_CTR_HMAC", 7), ("SP800_56A_CONCAT", 7),
            ("TLS1_1_KDF", 7), ("TLS1_2_KDF", 7), ("HKDF", 7),
        };

        internal static bool IsResolveRequest(ReadOnlySpan<byte> Input)
        {
            return Input.Length >= 8
                && BinaryPrimitives.ReadUInt32LittleEndian(Input) == RequestMagic
                && BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(4)) == RequestResolveProviders;
        }

        internal static NTSTATUS Resolve(BinaryEmulator Instance, ref DeviceData Data)
        {
            ReadOnlySpan<byte> Input = Data.InputBuffer.AsSpan(0, (int)Math.Min(Data.InputLength, (uint)Data.InputBuffer.Length));
            if (Input.Length < HeaderSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint RequestedInterface = BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(InterfaceOffset));
            uint Mode = BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(ModeOffset));
            string Function = ReadRequestString(Input, FunctionOffset);
            string Provider = ReadRequestString(Input, ProviderOffset);

            if ((Mode & CryptModeMask & CryptUserMode) == 0)
                return NTSTATUS.STATUS_NOT_FOUND;

            if (Provider != null && !Provider.Equals(PrimitiveProvider, StringComparison.OrdinalIgnoreCase))
                return NTSTATUS.STATUS_NOT_FOUND;

            int MatchCount = 0;
            foreach ((string Name, uint Interface) Algorithm in Algorithms)
            {
                if (Matches(Algorithm, Function, RequestedInterface))
                    MatchCount++;
            }

            if (MatchCount == 0)
                return NTSTATUS.STATUS_NOT_FOUND;

            return WriteProviderRefs(Instance, ref Data, Function, RequestedInterface, MatchCount);
        }

        private static bool Matches((string Name, uint Interface) Algorithm, string Function, uint RequestedInterface)
        {
            if (Function != null && !Algorithm.Name.Equals(Function, StringComparison.OrdinalIgnoreCase))
                return false;

            return RequestedInterface == 0 || Algorithm.Interface == RequestedInterface;
        }

        private static string ReadRequestString(ReadOnlySpan<byte> Input, int OffsetField)
        {
            long Offset = BinaryPrimitives.ReadInt64LittleEndian(Input.Slice(OffsetField));
            if (Offset < 0 || Offset + 2 > Input.Length)
                return null;

            int End = (int)Offset;
            while (End + 1 < Input.Length && (Input[End] != 0 || Input[End + 1] != 0))
                End += 2;

            return Encoding.Unicode.GetString(Input.Slice((int)Offset, End - (int)Offset));
        }

        private static NTSTATUS WriteProviderRefs(BinaryEmulator Instance, ref DeviceData Data, string Function, uint RequestedInterface, int MatchCount)
        {
            int Pointer = Instance.WinHelper.PointerSize;
            int RefsSize = 2 * Pointer;
            int RefSize = 7 * Pointer;
            int ImageRefSize = 2 * Pointer;

            int Cursor = RefsSize;
            int PointerArray = Cursor;
            Cursor += MatchCount * Pointer;
            int FirstRef = Cursor;
            Cursor += MatchCount * RefSize;

            int[] ImageRefs = new int[MatchCount];
            int[] ImageStrings = new int[MatchCount];
            int[] ProviderStrings = new int[MatchCount];
            int[] FunctionStrings = new int[MatchCount];

            int Index = 0;
            foreach ((string Name, uint Interface) Algorithm in Algorithms)
            {
                if (!Matches(Algorithm, Function, RequestedInterface))
                    continue;

                ImageRefs[Index] = Cursor;
                Cursor += ImageRefSize;
                ImageStrings[Index] = Cursor;
                Cursor = AlignUp(Cursor + Encoding.Unicode.GetByteCount(PrimitiveImage) + 2, Pointer);
                ProviderStrings[Index] = Cursor;
                Cursor = AlignUp(Cursor + Encoding.Unicode.GetByteCount(PrimitiveProvider) + 2, Pointer);
                FunctionStrings[Index] = Cursor;
                Cursor = AlignUp(Cursor + Encoding.Unicode.GetByteCount(Algorithm.Name) + 2, Pointer);
                Index++;
            }

            uint Required = (uint)Cursor;
            if (Data.OutputBuffer == null || Data.OutputLength < Required)
            {
                if (Data.OutputBuffer != null && Data.OutputLength >= 4)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(0, 4), Required);
                    Data.Information = 4;
                }

                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Span<byte> Output = Data.OutputBuffer.AsSpan(0, (int)Required);
            Output.Clear();

            BinaryPrimitives.WriteUInt32LittleEndian(Output, (uint)MatchCount);
            WriteReference(Output, Pointer, Pointer, PointerArray);

            Index = 0;
            foreach ((string Name, uint Interface) Algorithm in Algorithms)
            {
                if (!Matches(Algorithm, Function, RequestedInterface))
                    continue;

                int Entry = FirstRef + Index * RefSize;
                WriteReference(Output, PointerArray + Index * Pointer, Pointer, Entry);

                BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(Entry), Algorithm.Interface);
                WriteReference(Output, Entry + Pointer, Pointer, FunctionStrings[Index]);
                WriteReference(Output, Entry + 2 * Pointer, Pointer, ProviderStrings[Index]);
                WriteReference(Output, Entry + 4 * Pointer, Pointer, NullReference);
                WriteReference(Output, Entry + 5 * Pointer, Pointer, ImageRefs[Index]);
                WriteReference(Output, Entry + 6 * Pointer, Pointer, NullReference);

                WriteReference(Output, ImageRefs[Index], Pointer, ImageStrings[Index]);
                BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(ImageRefs[Index] + Pointer), ImageFlagsUserMode);

                WriteString(Output, ImageStrings[Index], PrimitiveImage);
                WriteString(Output, ProviderStrings[Index], PrimitiveProvider);
                WriteString(Output, FunctionStrings[Index], Algorithm.Name);
                Index++;
            }

            Data.Information = Required;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteReference(Span<byte> Buffer, int Offset, int PointerSize, int Target)
        {
            ulong Value = Target == NullReference ? ulong.MaxValue : (ulong)Target;

            if (PointerSize == 8)
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), (uint)Value);
        }

        private static void WriteString(Span<byte> Buffer, int Offset, string Value)
        {
            Encoding.Unicode.GetBytes(Value, Buffer.Slice(Offset));
        }

        private static int AlignUp(int Value, int Alignment)
        {
            int Mask = Alignment - 1;
            return (Value + Mask) & ~Mask;
        }
    }
}
