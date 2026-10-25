using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows.RPC
{
    /// <summary>
    /// Marshalling for the NDR 2.0 transfer syntax (8a885d04-1ceb-11c9-9fe8-08002b104860), which is what
    /// the audio interfaces negotiate.
    /// </summary>
    internal struct Ndr20Writer
    {
        public const int ContextHandleSize = 20;

        private byte[] Buffer;
        private int Position;
        private uint NextReferentId;

        public Ndr20Writer(int Capacity)
        {
            Buffer = new byte[Math.Max(Capacity, 16)];
            Position = 0;
            NextReferentId = 0x00020000;
        }

        public void WriteUInt32(uint Value)
        {
            Reserve(4);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.AsSpan(Position, 4), Value);
            Position += 4;
        }

        public void WriteInt32(int Value)
        {
            WriteUInt32(unchecked((uint)Value));
        }

        public void WriteBytes(ReadOnlySpan<byte> Value)
        {
            Reserve(Value.Length);
            Value.CopyTo(Buffer.AsSpan(Position, Value.Length));
            Position += Value.Length;
        }

        public void WriteZeros(int Count)
        {
            Reserve(Count);
            Buffer.AsSpan(Position, Count).Clear();
            Position += Count;
        }

        public void WriteUtf16(ReadOnlySpan<char> Value)
        {
            int Bytes = Value.Length * sizeof(char);
            Reserve(Bytes);
            Encoding.Unicode.GetBytes(Value, Buffer.AsSpan(Position, Bytes));
            Position += Bytes;
        }

        public void WriteByte(byte Value)
        {
            Reserve(1);
            Buffer[Position++] = Value;
        }

        // The bytes are zero, and the span is valid until the next write.
        public Span<byte> Take(int Count)
        {
            Reserve(Count);
            Span<byte> Taken = Buffer.AsSpan(Position, Count);
            Position += Count;
            return Taken;
        }

        public void WriteUInt16(ushort Value)
        {
            Reserve(2);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.AsSpan(Position, 2), Value);
            Position += 2;
        }

        public void WriteUInt64(ulong Value)
        {
            AlignTo(8);
            Reserve(8);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.AsSpan(Position, 8), Value);
            Position += 8;
        }

        public void WriteFloat(float Value)
        {
            AlignTo(4);
            Reserve(4);
            BinaryPrimitives.WriteSingleLittleEndian(Buffer.AsSpan(Position, 4), Value);
            Position += 4;
        }

        /// <summary>
        /// Emits the referent id that stands in for a non-null unique pointer. The pointee follows it.
        /// </summary>
        public void WriteUniqueReferent()
        {
            WriteUInt32(NextReferentId);
            NextReferentId += 4;
        }

        public void WriteContextHandle(ReadOnlySpan<byte> Cookie)
        {
            AlignTo(4);
            Reserve(ContextHandleSize);
            Buffer.AsSpan(Position, ContextHandleSize).Clear();
            Cookie.Slice(0, Math.Min(ContextHandleSize, Cookie.Length)).CopyTo(Buffer.AsSpan(Position, ContextHandleSize));
            Position += ContextHandleSize;
        }

        public void WriteGuid(Guid Value)
        {
            AlignTo(4);
            Reserve(16);
            Value.TryWriteBytes(Buffer.AsSpan(Position, 16));
            Position += 16;
        }

        public void WriteUniqueUInt32(bool Present, uint Value)
        {
            if (!Present)
            {
                WriteUInt32(0);
                return;
            }

            WriteUniqueReferent();
            WriteUInt32(Value);
        }

        public void WriteContextHandle(Guid Uuid)
        {
            Span<byte> Cookie = stackalloc byte[ContextHandleSize];
            Cookie.Slice(0, 4).Clear();
            Uuid.TryWriteBytes(Cookie.Slice(4));
            WriteContextHandle(Cookie);
        }

        public static byte[] BuildContextHandleReply(Guid Uuid)
        {
            Ndr20Writer Writer = new Ndr20Writer(ContextHandleSize + 4);
            Writer.WriteContextHandle(Uuid);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        public void WriteSystemHandle(int HandleIndex)
        {
            AlignTo(4);
            WriteUInt32(HandleIndex < 0 ? 0u : (uint)HandleIndex + 1);
            WriteUInt32(0);
        }

        public void AlignTo(int Alignment)
        {
            int Padded = (Position + Alignment - 1) & ~(Alignment - 1);
            Reserve(Padded - Position);
            Buffer.AsSpan(Position, Padded - Position).Clear();
            Position = Padded;
        }

        // rpcrt4 pads before the elements of an array only when it has any.
        public void AlignArray(uint Count, int Alignment)
        {
            if (Count != 0)
                AlignTo(Alignment);
        }

        public void WriteUniqueWideString(string Value)
        {
            if (Value == null)
            {
                WriteUInt32(0);
                return;
            }

            WriteUInt32(NextReferentId);
            NextReferentId += 4;
            WriteConformantWideString(Value);
        }

        public void WriteConformantWideString(string Value)
        {
            AlignTo(4);
            uint CharCount = (uint)Value.Length + 1;
            WriteUInt32(CharCount);
            WriteUInt32(0);
            WriteUInt32(CharCount);
            WriteUtf16(Value);
            WriteUInt16(0);
            AlignTo(4);
        }

        public readonly ReadOnlySpan<byte> Written => Buffer.AsSpan(0, Position);

        public byte[] ToArray()
        {
            byte[] Result = new byte[Position];
            Array.Copy(Buffer, Result, Position);
            return Result;
        }

        private void Reserve(int Count)
        {
            if (Position + Count <= Buffer.Length)
                return;

            int Capacity = Buffer.Length;
            while (Capacity < Position + Count)
                Capacity *= 2;

            Array.Resize(ref Buffer, Capacity);
        }
    }

    internal ref struct Ndr20Reader
    {
        private readonly ReadOnlySpan<byte> Data;
        private int Position;

        public Ndr20Reader(ReadOnlySpan<byte> Data)
        {
            this.Data = Data;
            Position = 0;
        }

        public bool TryReadUInt16(out ushort Value)
        {
            Value = 0;
            Align(2);
            if (Position + 2 > Data.Length)
                return false;

            Value = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(Position, 2));
            Position += 2;
            return true;
        }

        public bool TryReadUInt32(out uint Value)
        {
            Value = 0;
            Align(4);
            if (Position + 4 > Data.Length)
                return false;

            Value = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(Position, 4));
            Position += 4;
            return true;
        }

        public bool TryReadUInt64(out ulong Value)
        {
            Value = 0;
            Align(8);
            if (Position + 8 > Data.Length)
                return false;

            Value = BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(Position, 8));
            Position += 8;
            return true;
        }

        public bool TryReadContextHandle(out ReadOnlySpan<byte> Cookie)
        {
            Cookie = default;
            Align(4);
            if (Position + Ndr20Writer.ContextHandleSize > Data.Length)
                return false;

            Cookie = Data.Slice(Position, Ndr20Writer.ContextHandleSize);
            Position += Ndr20Writer.ContextHandleSize;
            return true;
        }

        public void Align(int Alignment)
        {
            Position = (Position + Alignment - 1) & ~(Alignment - 1);
        }

        public void AlignArray(uint Count, int Alignment)
        {
            if (Count != 0)
                Align(Alignment);
        }

        public bool TrySkip(int Count) => TryReadBytes(Count, out _);

        public bool TryReadBytes(int Count, out ReadOnlySpan<byte> Value)
        {
            Value = default;
            if (Count < 0 || Count > Data.Length - Position)
                return false;

            Value = Data.Slice(Position, Count);
            Position += Count;
            return true;
        }

        public bool TryReadFloat(out float Value)
        {
            bool Read = TryReadUInt32(out uint Bits);
            Value = BitConverter.UInt32BitsToSingle(Bits);
            return Read;
        }

        public bool TryReadGuid(out Guid Value)
        {
            Value = Guid.Empty;
            Align(4);
            if (!TryReadBytes(16, out ReadOnlySpan<byte> Bytes))
                return false;

            Value = new Guid(Bytes);
            return true;
        }

        public bool TryReadUniqueGuid(out Guid Value)
        {
            Value = Guid.Empty;

            if (!TryReadUInt32(out uint ReferentId))
                return false;

            return ReferentId == 0 || TryReadGuid(out Value);
        }

        public bool TryReadUniqueUInt32(out bool Present, out uint Value)
        {
            Present = false;
            Value = 0;

            if (!TryReadUInt32(out uint ReferentId))
                return false;

            Present = ReferentId != 0;
            return !Present || TryReadUInt32(out Value);
        }

        public bool TryReadConformantWideString(out string Value)
        {
            Value = null;
            if (!TryReadConformantWideChars(out ReadOnlySpan<byte> Chars, out _))
                return false;

            Value = Encoding.Unicode.GetString(MemoryMarshal.AsBytes(MemoryMarshal.Cast<byte, char>(Chars).TrimEnd('\0')));
            return true;
        }

        public bool TryReadConformantWideChars(out ReadOnlySpan<byte> Chars, out uint Offset)
        {
            Chars = default;
            Offset = 0;
            if (!TryReadUInt32(out uint MaxCount) || !TryReadUInt32(out Offset) || !TryReadUInt32(out uint ActualCount))
                return false;

            if (ActualCount > MaxCount || ActualCount > (uint)(Data.Length - Position) / 2)
                return false;

            return TryReadBytes((int)ActualCount * 2, out Chars);
        }

        public bool TryReadUniqueWideString(out string Value)
        {
            Value = null;

            if (!TryReadUInt32(out uint ReferentId))
                return false;

            return ReferentId == 0 || TryReadConformantWideString(out Value);
        }
    }
}
