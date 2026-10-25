using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows.RPC
{
    internal readonly struct CoreMessagingBuffer
    {
        internal const int HeaderSize = 0x28;
        private const int OffReservedZero = 0x00;
        private const int OffKind = 0x10;
        private const int OffSequence = 0x14;
        private const int OffBatchIndex = 0x18;
        private const int OffBatchCount = 0x1A;
        private const int OffPayloadLength = 0x20;
        private const uint KindMask = 0x27;
        private const uint KindChunked = 0x10;
        private const uint KindNoResult = 0x08;

        internal const uint KindReply = 0;
        internal const uint KindOneWay = 1;
        internal const uint KindCall = 2;
        internal const uint KindPing = 4;

        private const int OffPingHasResult = HeaderSize;
        private const int PingReplySize = HeaderSize + 8;

        internal readonly uint Kind;
        internal readonly uint Sequence;
        internal readonly bool WantsResult;
        internal readonly ushort BatchIndex;
        internal readonly ushort BatchCount;

        private CoreMessagingBuffer(uint Kind, uint Sequence, bool WantsResult, ushort BatchIndex, ushort BatchCount)
        {
            this.Kind = Kind;
            this.Sequence = Sequence;
            this.WantsResult = WantsResult;
            this.BatchIndex = BatchIndex;
            this.BatchCount = BatchCount;
        }

        // The checks follow AlpcConnection::ValidateBufferHeader in coremessaging. Chunked buffers are refused.
        internal static bool TryRead(ReadOnlySpan<byte> Data, out CoreMessagingBuffer Header, out ReadOnlySpan<byte> Payload)
        {
            Header = default;
            Payload = default;
            if (Data.Length < HeaderSize)
                return false;

            uint RawKind = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(OffKind));
            uint Kind = RawKind & KindMask;
            uint PayloadLength = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(OffPayloadLength));
            ushort BatchIndex = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(OffBatchIndex));
            ushort BatchCount = BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(OffBatchCount));
            if (BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(OffReservedZero)) != 0
                || PayloadLength != (uint)(Data.Length - HeaderSize)
                || (RawKind & KindChunked) != 0
                || (Kind != KindOneWay && Kind != KindCall && Kind != KindPing)
                || BatchIndex >= BatchCount
                || (Kind != KindOneWay && BatchCount != 1))
                return false;

            Header = new CoreMessagingBuffer(Kind, BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(OffSequence)), (RawKind & KindNoResult) == 0, BatchIndex, BatchCount);
            Payload = Data.Slice(HeaderSize);
            return true;
        }

        internal static void Write(Span<byte> Buffer, uint Kind, uint Sequence, int PayloadLength)
        {
            Buffer.Slice(0, HeaderSize).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(OffKind), Kind);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(OffSequence), Sequence);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(OffBatchCount), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(OffPayloadLength), (uint)PayloadLength);
        }

        // NT leaves the payload length of a ping reply 0, though the flag and the result follow the header.
        internal static byte[] PingReply(uint Sequence, bool HasResult, ReadOnlySpan<byte> Result)
        {
            byte[] Reply = new byte[PingReplySize + Result.Length];
            Write(Reply, KindReply, Sequence, 0);
            Reply[OffPingHasResult] = HasResult ? (byte)1 : (byte)0;
            Result.CopyTo(Reply.AsSpan(PingReplySize));
            return Reply;
        }
    }

    // NT: ReceiveProcessor::UnmarshalReceive and CnSerializeRead::UnformatInvoke. Each parameter is a u32 size and its
    // bytes padded to 4, and the parameters fill the call exactly.
    internal ref struct CoreMessagingReader
    {
        private ReadOnlySpan<byte> Remaining;

        internal CoreMessagingReader(ReadOnlySpan<byte> Parameters) => Remaining = Parameters;

        internal bool AtEnd => Remaining.IsEmpty;

        internal bool TryReadFixed(int Size, out ReadOnlySpan<byte> Value) => TryReadNext(out Value) && Value.Length == Size;

        internal bool TryReadUInt32(out uint Value)
        {
            Value = 0;
            if (!TryReadFixed(4, out ReadOnlySpan<byte> Bytes))
                return false;

            Value = BinaryPrimitives.ReadUInt32LittleEndian(Bytes);
            return true;
        }

        internal bool TryReadUInt64(out ulong Value)
        {
            Value = 0;
            if (!TryReadFixed(8, out ReadOnlySpan<byte> Bytes))
                return false;

            Value = BinaryPrimitives.ReadUInt64LittleEndian(Bytes);
            return true;
        }

        internal bool TryReadBool(out bool Value)
        {
            Value = false;
            if (!TryReadFixed(1, out ReadOnlySpan<byte> Bytes))
                return false;

            Value = Bytes[0] != 0;
            return true;
        }

        internal bool TryReadGuid(out Guid Value)
        {
            Value = default;
            if (!TryReadFixed(16, out ReadOnlySpan<byte> Bytes))
                return false;

            Value = new Guid(Bytes);
            return true;
        }

        // A null string has size 0, any other ends in NUL. The value stops at the first NUL.
        internal bool TryReadString(out ReadOnlySpan<char> Value)
        {
            Value = default;
            if (!TryReadNext(out ReadOnlySpan<byte> Bytes) || (Bytes.Length & 1) != 0)
                return false;

            if (Bytes.IsEmpty)
                return true;

            ReadOnlySpan<char> Chars = MemoryMarshal.Cast<byte, char>(Bytes);
            if (Chars[^1] != '\0')
                return false;

            Value = Chars.Slice(0, Chars.IndexOf('\0'));
            return true;
        }

        // An out parameter is a slot of size 0. Its value goes back in the reply to the ping that follows the call.
        internal bool TryReadOutSlot() => TryReadNext(out ReadOnlySpan<byte> Value) && Value.IsEmpty;

        internal bool TryReadNext(out ReadOnlySpan<byte> Value)
        {
            Value = default;
            if (Remaining.Length < 4)
                return false;

            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Remaining);
            ReadOnlySpan<byte> Rest = Remaining.Slice(4);
            if (Size > (uint)Rest.Length || ((Size + 3) & ~3u) > (uint)Rest.Length)
                return false;

            Value = Rest.Slice(0, (int)Size);
            Remaining = Rest.Slice((int)((Size + 3) & ~3u));
            return true;
        }
    }

    internal sealed class CoreMessagingWriter
    {
        private static readonly byte[] Padding = new byte[3];

        private readonly ArrayBufferWriter<byte> Parameters = new ArrayBufferWriter<byte>(0x40);

        internal ReadOnlySpan<byte> Written => Parameters.WrittenSpan;

        internal void Clear() => Parameters.ResetWrittenCount();

        internal void UInt32(uint Value)
        {
            Span<byte> Bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes, Value);
            this.Bytes(Bytes);
        }

        internal void UInt64(ulong Value)
        {
            Span<byte> Bytes = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(Bytes, Value);
            this.Bytes(Bytes);
        }

        internal void Bool(bool Value)
        {
            Span<byte> Bytes = stackalloc byte[1];
            Bytes[0] = Value ? (byte)1 : (byte)0;
            this.Bytes(Bytes);
        }

        internal void Guid(Guid Value)
        {
            Span<byte> Bytes = stackalloc byte[16];
            Value.TryWriteBytes(Bytes);
            this.Bytes(Bytes);
        }

        internal void String(string Value)
        {
            if (Value == null)
            {
                Bytes(ReadOnlySpan<byte>.Empty);
                return;
            }

            int Size = (Value.Length + 1) * sizeof(char);
            int Padded = sizeof(uint) + ((Size + 3) & ~3);
            Span<byte> Field = Parameters.GetSpan(Padded).Slice(0, Padded);
            BinaryPrimitives.WriteUInt32LittleEndian(Field, (uint)Size);
            MemoryMarshal.AsBytes(Value.AsSpan()).CopyTo(Field.Slice(sizeof(uint)));
            Field.Slice(sizeof(uint) + Value.Length * sizeof(char)).Clear();
            Parameters.Advance(Padded);
        }

        internal void Bytes(ReadOnlySpan<byte> Value)
        {
            Span<byte> Size = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Size, (uint)Value.Length);
            Parameters.Write(Size);
            Parameters.Write(Value);
            Parameters.Write(Padding.AsSpan(0, -Value.Length & 3));
        }
    }

    internal static class CoreMessagingCall
    {
        internal const int HeaderSize = 8;

        internal static bool TryRead(ReadOnlySpan<byte> Payload, out ushort Interface, out ushort Method, out CoreMessagingReader Parameters)
        {
            Interface = 0;
            Method = 0;
            Parameters = default;
            if (Payload.Length < HeaderSize)
                return false;

            uint SizeInDwords = BinaryPrimitives.ReadUInt32LittleEndian(Payload);
            Interface = BinaryPrimitives.ReadUInt16LittleEndian(Payload.Slice(4));
            Method = BinaryPrimitives.ReadUInt16LittleEndian(Payload.Slice(6));
            Parameters = new CoreMessagingReader(Payload.Slice(HeaderSize));
            return (ulong)SizeInDwords * 4 == (ulong)Payload.Length;
        }

        internal static void WriteHeader(Span<byte> Header, ushort Interface, ushort Method, int ParametersLength)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)((HeaderSize + ParametersLength) / 4));
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(4), Interface);
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(6), Method);
        }

        // NT: AlpcServerConnection::PostSynchronousCallResponse gives the reply the sequence of its request.
        internal static byte[] ToReply(ushort Interface, ushort Method, uint Sequence, CoreMessagingWriter Parameters)
        {
            ReadOnlySpan<byte> Written = Parameters != null ? Parameters.Written : ReadOnlySpan<byte>.Empty;
            int PayloadLength = HeaderSize + Written.Length;
            byte[] Reply = new byte[CoreMessagingBuffer.HeaderSize + PayloadLength];
            CoreMessagingBuffer.Write(Reply, CoreMessagingBuffer.KindReply, Sequence, PayloadLength);
            Span<byte> Call = Reply.AsSpan(CoreMessagingBuffer.HeaderSize);
            WriteHeader(Call, Interface, Method, Written.Length);
            Written.CopyTo(Call.Slice(HeaderSize));
            return Reply;
        }
    }

    internal ref struct CoreMessagingBatchReader
    {
        internal const int MessageHeaderSize = 16;
        internal const int Alignment = 16;

        private ReadOnlySpan<byte> Remaining;

        internal CoreMessagingBatchReader(ReadOnlySpan<byte> Batch) => Remaining = Batch;

        internal bool TryReadNext(out ulong Target, out ReadOnlySpan<byte> Payload)
        {
            Target = 0;
            Payload = default;
            if (Remaining.Length < MessageHeaderSize)
                return false;

            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Remaining.Slice(8));
            if (Size < MessageHeaderSize || Size > (uint)Remaining.Length)
                return false;

            Target = BinaryPrimitives.ReadUInt64LittleEndian(Remaining);
            Payload = Remaining.Slice(MessageHeaderSize, (int)Size - MessageHeaderSize);
            int Padded = (int)Math.Min((Size + Alignment - 1) & ~(uint)(Alignment - 1), (uint)Remaining.Length);
            Remaining = Remaining.Slice(Padded);
            return true;
        }
    }

    internal sealed class CoreMessagingBatchWriter
    {
        private readonly ArrayBufferWriter<byte> Messages = new ArrayBufferWriter<byte>(0x100);

        internal bool IsEmpty => Messages.WrittenCount == 0;

        internal int Length => Messages.WrittenCount;

        internal void Add(ulong Target, ReadOnlySpan<byte> Header, ReadOnlySpan<byte> Body)
        {
            int Size = CoreMessagingBatchReader.MessageHeaderSize + Header.Length + Body.Length;
            int Padded = (Size + CoreMessagingBatchReader.Alignment - 1) & ~(CoreMessagingBatchReader.Alignment - 1);
            Span<byte> Message = Messages.GetSpan(Padded).Slice(0, Padded);
            Message.Clear();
            BinaryPrimitives.WriteUInt64LittleEndian(Message, Target);
            BinaryPrimitives.WriteUInt32LittleEndian(Message.Slice(8), (uint)Size);
            Header.CopyTo(Message.Slice(CoreMessagingBatchReader.MessageHeaderSize));
            Body.CopyTo(Message.Slice(CoreMessagingBatchReader.MessageHeaderSize + Header.Length));
            Messages.Advance(Padded);
        }

        internal byte[] ToBuffer(uint Sequence)
        {
            byte[] Buffer = new byte[CoreMessagingBuffer.HeaderSize + Messages.WrittenCount];
            CoreMessagingBuffer.Write(Buffer, CoreMessagingBuffer.KindOneWay, Sequence, Messages.WrittenCount);
            Messages.WrittenSpan.CopyTo(Buffer.AsSpan(CoreMessagingBuffer.HeaderSize));
            return Buffer;
        }

        internal void Clear() => Messages.ResetWrittenCount();
    }

    internal static class CoreMessagingRouting
    {
        internal const int Size = 40;
        private const int OffThreadId = 4;
        private const int OffIdentity = 8;
        private const int OffClientId = 16;
        private const int OffPort = 24;

        internal static void Write(Span<byte> Routing, uint ProcessId, uint ThreadId, ulong Identity, ulong ClientId, Guid Port)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Routing, ProcessId);
            BinaryPrimitives.WriteUInt32LittleEndian(Routing.Slice(OffThreadId), ThreadId);
            BinaryPrimitives.WriteUInt64LittleEndian(Routing.Slice(OffIdentity), Identity);
            BinaryPrimitives.WriteUInt64LittleEndian(Routing.Slice(OffClientId), ClientId);
            Port.TryWriteBytes(Routing.Slice(OffPort));
        }

        internal static uint ProcessId(ReadOnlySpan<byte> Routing) => BinaryPrimitives.ReadUInt32LittleEndian(Routing);

        internal static uint ThreadId(ReadOnlySpan<byte> Routing) => BinaryPrimitives.ReadUInt32LittleEndian(Routing.Slice(OffThreadId));

        internal static ulong Identity(ReadOnlySpan<byte> Routing) => BinaryPrimitives.ReadUInt64LittleEndian(Routing.Slice(OffIdentity));

        internal static ulong ClientId(ReadOnlySpan<byte> Routing) => BinaryPrimitives.ReadUInt64LittleEndian(Routing.Slice(OffClientId));

        internal static void SetIdentity(Span<byte> Routing, ulong Identity) => BinaryPrimitives.WriteUInt64LittleEndian(Routing.Slice(OffIdentity), Identity);
    }

    internal sealed class LowestFreeIds
    {
        private readonly SortedSet<uint> Free = new SortedSet<uint>();
        private readonly uint First;
        private readonly uint Limit;
        private uint Next;

        internal LowestFreeIds(uint First, uint Limit)
        {
            this.First = First;
            this.Limit = Limit;
            Next = First;
        }

        internal bool TryTake(out uint Id)
        {
            if (Free.Count != 0)
            {
                Id = Free.Min;
                Free.Remove(Id);
                return true;
            }

            Id = 0;
            if (Next >= Limit)
                return false;

            Id = Next++;
            return true;
        }

        internal bool IsTaken(uint Id) => Id >= First && Id < Next && !Free.Contains(Id);

        internal void Release(uint Id)
        {
            if (Id >= First && Id < Next)
                Free.Add(Id);
        }
    }

    // NT counts the generation of an index in 16 bits from 1, though the field has 25 (HIDENTITYAllocator).
    internal sealed class HIdentityAllocator
    {
        internal const int MaxLive = 0x200000;
        private const int GenerationShift = 21;
        private const int GroupShift = 46;
        private const ulong IndexMask = (1UL << GenerationShift) - 1;
        private const ulong GenerationMask = (1UL << (GroupShift - GenerationShift)) - 1;

        internal readonly uint Group;
        private readonly List<ushort> Generations = new List<ushort>();
        private readonly LowestFreeIds Indices = new LowestFreeIds(0, MaxLive);

        // RemoteRegistrarServer::RegisterThread allocates the two session identities of a thread group.
        internal HIdentityAllocator(uint Group, bool ThreadGroup)
        {
            this.Group = Group;
            if (ThreadGroup)
            {
                TryAllocate(out _);
                TryAllocate(out _);
            }
        }

        internal static ulong SessionIdentity(uint Group, int Number) => Make(Group, (uint)Number, 1);

        internal static uint GroupOf(ulong Identity) => (uint)(Identity >> GroupShift);

        private static ulong Make(uint Group, uint Index, uint Generation) => Index | ((ulong)Generation << GenerationShift) | ((ulong)Group << GroupShift);

        internal bool Owns(ulong Identity) => GroupOf(Identity) == Group;

        internal bool TryAllocate(out ulong Identity)
        {
            Identity = 0;
            if (!Indices.TryTake(out uint Index))
                return false;

            if (Index == Generations.Count)
                Generations.Add(0);

            ushort Generation = (ushort)(Generations[(int)Index] + 1);
            if (Generation == 0)
                Generation = 1;
            Generations[(int)Index] = Generation;
            Identity = Make(Group, Index, Generation);
            return true;
        }

        internal bool IsLive(ulong Identity)
        {
            uint Index = (uint)(Identity & IndexMask);
            return Owns(Identity) && Indices.IsTaken(Index) && Generations[(int)Index] == ((Identity >> GenerationShift) & GenerationMask);
        }

        internal void Free(ulong Identity)
        {
            if (IsLive(Identity))
                Indices.Release((uint)(Identity & IndexMask));
        }
    }
}
