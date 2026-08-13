using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.RPC
{
    internal enum LrpcMessageType : ulong
    {
        Request = 0,
        Bind = 1,
        Fault = 2,
        Response = 3,
    }

    internal readonly struct LrpcMessage
    {
        public readonly byte[] Raw;
        public readonly LrpcMessageType Type;
        public readonly uint CallId;
        public readonly uint ProcNumber;
        public readonly uint SyntaxMask;

        public LrpcMessage(byte[] Raw, LrpcMessageType Type, uint CallId, uint ProcNumber, uint SyntaxMask)
        {
            this.Raw = Raw;
            this.Type = Type;
            this.CallId = CallId;
            this.ProcNumber = ProcNumber;
            this.SyntaxMask = SyntaxMask;
        }

        public ReadOnlySpan<byte> StubData =>
            Raw != null && Raw.Length > LrpcPacket.RequestStubDataOffset
                ? Raw.AsSpan(LrpcPacket.RequestStubDataOffset)
                : ReadOnlySpan<byte>.Empty;
    }

    internal static class LrpcPacket
    {
        public const int HeaderSize = 0x28; // x64 PORT_MESSAGE
        public const int StubDataOffset = 0x40;
        public const int RequestStubDataOffset = StubDataOffset + 0x28;
        private const int OffMessageType = 0x00;
        private const int OffStatus = 0x08;
        private const int OffCallId = 0x0C;
        private const int OffProcNumber = 0x14;
        private const int OffSyntaxMask = 0x20;

        public static bool TryParse(byte[] Message, out LrpcMessage Parsed)
        {
            Parsed = default;

            if (Message == null || Message.Length < HeaderSize + 8)
                return false;

            ReadOnlySpan<byte> Payload = Message.AsSpan(HeaderSize);
            LrpcMessageType Type = (LrpcMessageType)BinaryPrimitives.ReadUInt64LittleEndian(Payload.Slice(OffMessageType, 8));

            Parsed = new LrpcMessage(
                Message,
                Type,
                ReadPayloadU32(Payload, OffCallId),
                ReadPayloadU32(Payload, OffProcNumber),
                ReadPayloadU32(Payload, OffSyntaxMask));

            return true;
        }

        public static byte[] BuildBindAccept(in LrpcMessage Request, out uint AcceptedSyntax)
        {
            AcceptedSyntax = Request.SyntaxMask & (uint)(-(int)Request.SyntaxMask);
            if (AcceptedSyntax == 0 || Request.Raw.Length < HeaderSize + OffSyntaxMask + 4)
                return null;

            byte[] Reply = (byte[])Request.Raw.Clone();
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(HeaderSize + OffSyntaxMask, 4), AcceptedSyntax);
            return Reply;
        }

        public static byte[] BuildResponse(in LrpcMessage Request, ReadOnlySpan<byte> StubData)
        {
            byte[] Reply = NewReply(Request, StubData.Length, LrpcMessageType.Response, 0);
            StubData.CopyTo(Reply.AsSpan(StubDataOffset));
            return Reply;
        }

        public static byte[] BuildFault(in LrpcMessage Request, uint Status)
        {
            return NewReply(Request, 0, LrpcMessageType.Fault, Status);
        }

        private static byte[] NewReply(in LrpcMessage Request, int StubLength, LrpcMessageType Type, uint Status)
        {
            byte[] Reply = new byte[StubDataOffset + StubLength];
            Array.Copy(Request.Raw, Reply, Math.Min(HeaderSize, Request.Raw.Length));

            Span<byte> Payload = Reply.AsSpan(HeaderSize);
            BinaryPrimitives.WriteUInt64LittleEndian(Payload.Slice(OffMessageType, 8), (ulong)Type);
            BinaryPrimitives.WriteUInt32LittleEndian(Payload.Slice(OffStatus, 4), Status);
            BinaryPrimitives.WriteUInt32LittleEndian(Payload.Slice(OffCallId, 4), Request.CallId);
            return Reply;
        }

        private static uint ReadPayloadU32(ReadOnlySpan<byte> Payload, int Offset)
        {
            return Payload.Length < Offset + 4 ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(Offset, 4));
        }
    }
}
