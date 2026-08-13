using System;
using System.Buffers.Binary;
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

        public void WriteUniqueWideString(string Value)
        {
            if (Value == null)
            {
                WriteUInt32(0);
                return;
            }

            WriteUInt32(NextReferentId);
            NextReferentId += 4;

            uint CharCount = (uint)Value.Length + 1;
            WriteUInt32(CharCount);
            WriteUInt32(0);
            WriteUInt32(CharCount);

            int Bytes = (int)CharCount * 2;
            Reserve(Bytes);
            Buffer.AsSpan(Position, Bytes).Clear();
            Encoding.Unicode.GetBytes(Value, Buffer.AsSpan(Position, Bytes - 2));
            Position += Bytes;
            AlignTo(4);
        }

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
            if (Position + 2 > Data.Length)
                return false;

            Value = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(Position, 2));
            Position += 2;
            return true;
        }

        public bool TryReadUInt32(out uint Value)
        {
            Value = 0;
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

        public bool TryReadConformantWideString(out string Value)
        {
            Value = null;

            if (!TryReadUInt32(out uint MaxCount) || !TryReadUInt32(out _) || !TryReadUInt32(out uint ActualCount))
                return false;

            if (ActualCount > MaxCount)
                return false;

            if (ActualCount > (uint)(Data.Length - Position) / 2)
                return false;

            int Bytes = (int)ActualCount * 2;

            Value = Encoding.Unicode.GetString(Data.Slice(Position, Bytes)).TrimEnd('\0');
            Position += (Bytes + 3) & ~3;
            return true;
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
