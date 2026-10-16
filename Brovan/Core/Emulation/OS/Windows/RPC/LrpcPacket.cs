using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Helpers;

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

    internal static class LrpcBindings
    {
        // The checks and their order follow LRPC_SASSOCIATION::AddBinding in rpcrt4.
        // False means the interface is not served here.
        public static bool TryAccept(ServedClient Client, in LrpcMessage Request, ReadOnlySpan<Guid> Interfaces, out Guid Interface, out byte[] Answer)
        {
            Answer = null;
            uint Offered = Request.SyntaxMask & LrpcPacket.OfferedSyntaxes;
            if (!LrpcPacket.TryReadBind(Request, out Interface, out ushort Context) || Offered == 0 || Offered == LrpcPacket.OfferedSyntaxes)
            {
                Answer = LrpcPacket.BuildFault(Request, LrpcPacket.RpcSProtocolError);
                return true;
            }

            if (!Interfaces.Contains(Interface))
                return false;

            if ((Offered & LrpcPacket.SyntaxNdr20) == 0)
            {
                Answer = LrpcPacket.BuildFault(Request, LrpcPacket.RpcSUnsupportedTransferSyntax);
                return true;
            }

            Client.Bindings ??= new Dictionary<uint, Guid>();
            Client.Bindings[Context] = Interface;
            Answer = LrpcPacket.BuildBindAccept(Request, out _);
            return true;
        }

        public static bool TryResolve(ServedClient Client, in LrpcMessage Request, out Guid Interface, out Guid ObjectId)
        {
            Interface = Guid.Empty;
            return LrpcPacket.TryReadRequestTarget(Request, out uint Context, out ObjectId) && Client.Bindings != null
                && Client.Bindings.TryGetValue(Context, out Interface);
        }
    }

    internal static class LrpcPacket
    {
        public const int HeaderSize = 0x28; // x64 PORT_MESSAGE
        public const int StubDataOffset = 0x40;
        public const int RequestStubDataOffset = StubDataOffset + 0x28;
        public const int ResponsePayloadStubOffset = StubDataOffset - HeaderSize;
        private const int RequestPayloadStubOffset = RequestStubDataOffset - HeaderSize;
        private const int OffMessageType = 0x00;
        private const int OffStatus = 0x08;
        private const int OffFlags = 0x08;
        private const int OffCallId = 0x0C;
        private const int OffContext = 0x10;
        private const int OffProcNumber = 0x14;
        private const int OffSyntaxMask = 0x20;
        private const int OffObjectUuid = 0x30;
        private const uint RequestObjectUuid = 1;

        // rpcrt4 builds this bind message in LRPC_CASSOCIATION::Bind.
        private const int BindSize = 0x48;
        private const int OffBindInterface = 0x0C;
        private const int OffBindNdr20Context = 0x24;
        private const int OffBindAssociationTick = 0x40;
        public const uint SyntaxNdr20 = 1;
        public const uint OfferedSyntaxes = 7;

        // rpcrt4 refuses a response shorter than a fault, or one whose stub is in a view (LRPC_BASE_CCALL::UnpackResponse).
        private const int MinFaultSize = 0x10;
        private const uint ResponseInView = 4;

        // A larger reply stub needs a view, which the ports Brovan serves never send (LRPC_SCALL::GetBuffer).
        public const int MaxResponseStubLength = 0xFC0;

        public const uint RpcOk = 0;
        public const uint RpcSUnknownIf = 1717;
        public const uint RpcSServerUnavailable = 1722;
        public const uint RpcSCallFailedDne = 1727;
        public const uint RpcSProtocolError = 1728;
        public const uint RpcSUnsupportedTransferSyntax = 1730;
        public const uint RpcSProcnumOutOfRange = 1745;
        public const uint RpcSCannotSupport = 1764;
        public const uint RpcXBadStubData = 1783;

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

        // rpcrt4 gives each offered transfer syntax its own context id, NDR20 first, and the requests name the one accepted.
        public static bool TryReadBind(in LrpcMessage Request, out Guid Interface, out ushort Ndr20Context)
        {
            Interface = Guid.Empty;
            Ndr20Context = 0;
            if (Request.Raw.Length < HeaderSize + BindSize)
                return false;

            Interface = new Guid(Request.Raw.AsSpan(HeaderSize + OffBindInterface, 16));
            Ndr20Context = BinaryPrimitives.ReadUInt16LittleEndian(Request.Raw.AsSpan(HeaderSize + OffBindNdr20Context, 2));
            return true;
        }

        public static bool TryReadRequestTarget(in LrpcMessage Request, out uint Context, out Guid ObjectId)
        {
            Context = 0;
            ObjectId = Guid.Empty;
            if (Request.Raw.Length < RequestStubDataOffset)
                return false;

            ReadOnlySpan<byte> Payload = Request.Raw.AsSpan(HeaderSize);
            Context = BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(OffContext));
            if ((BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(OffFlags)) & RequestObjectUuid) != 0)
                ObjectId = new Guid(Payload.Slice(OffObjectUuid, 16));
            return true;
        }

        public static byte[] BuildResponse(in LrpcMessage Request, ReadOnlySpan<byte> StubData)
        {
            if (StubData.Length > MaxResponseStubLength)
            {
                Utils.LogError($"[-] LRPC: a reply stub of 0x{StubData.Length:X} bytes needs a view, which is not supported.");
                return BuildFault(Request, RpcSCannotSupport);
            }

            byte[] Reply = NewReply(Request, StubData.Length, LrpcMessageType.Response, 0);
            StubData.CopyTo(Reply.AsSpan(StubDataOffset));
            return Reply;
        }

        public static byte[] BuildFault(in LrpcMessage Request, uint Status)
        {
            return NewReply(Request, 0, LrpcMessageType.Fault, Status);
        }

        public static byte[] BuildBindPayload(Guid Interface, ushort Context, uint AssociationTick)
        {
            byte[] Payload = new byte[BindSize];
            Span<byte> Span = Payload;
            BinaryPrimitives.WriteUInt64LittleEndian(Span.Slice(OffMessageType), (ulong)LrpcMessageType.Bind);
            Interface.TryWriteBytes(Span.Slice(OffBindInterface, 16));
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(OffSyntaxMask), SyntaxNdr20);
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(OffBindNdr20Context), Context);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(OffBindAssociationTick), AssociationTick);
            return Payload;
        }

        public static byte[] BuildRequestPayload(uint CallId, ushort Context, uint ProcNumber, Guid ObjectId, ReadOnlySpan<byte> StubData)
        {
            byte[] Payload = new byte[RequestPayloadStubOffset + StubData.Length];
            Span<byte> Span = Payload;
            BinaryPrimitives.WriteUInt64LittleEndian(Span.Slice(OffMessageType), (ulong)LrpcMessageType.Request);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(OffCallId), CallId);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(OffContext), Context);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(OffProcNumber), ProcNumber);
            if (ObjectId != Guid.Empty)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(OffFlags), RequestObjectUuid);
                ObjectId.TryWriteBytes(Span.Slice(OffObjectUuid, 16));
            }
            StubData.CopyTo(Span.Slice(RequestPayloadStubOffset));
            return Payload;
        }

        // rpcrt4 reads any type but a fault as a bind answer, and turns a zero fault status into a protocol error.
        public static uint ParseBindAnswer(ReadOnlySpan<byte> Payload)
        {
            if (Payload.Length < MinFaultSize)
                return RpcSProtocolError;

            if (BinaryPrimitives.ReadUInt64LittleEndian(Payload) == (ulong)LrpcMessageType.Fault)
                return FaultStatus(Payload);

            if (Payload.Length < OffSyntaxMask + 4)
                return RpcSProtocolError;

            uint Accepted = BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(OffSyntaxMask));
            if (Accepted == 0)
                return RpcSUnsupportedTransferSyntax;

            return Accepted == SyntaxNdr20 ? RpcOk : RpcSProtocolError;
        }

        public static uint ParseResponse(ReadOnlySpan<byte> Payload, uint CallId)
        {
            if (Payload.Length < MinFaultSize)
                return RpcSProtocolError;

            if (BinaryPrimitives.ReadUInt64LittleEndian(Payload) != (ulong)LrpcMessageType.Response)
                return FaultStatus(Payload);

            if (Payload.Length < ResponsePayloadStubOffset
                || (BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(OffFlags)) & ResponseInView) != 0
                || BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(OffCallId)) != CallId)
                return RpcSProtocolError;

            return RpcOk;
        }

        public static byte[] EchoHeader(byte[] Request)
        {
            byte[] Reply = new byte[HeaderSize];
            Array.Copy(Request, Reply, Math.Min(HeaderSize, Request.Length));
            return Reply;
        }

        private static uint FaultStatus(ReadOnlySpan<byte> Payload)
        {
            uint Status = BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(OffStatus));
            return Status != 0 ? Status : RpcSProtocolError;
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

    // The response stub is in the shared scratch buffer, so it is valid only during the call.
    internal delegate void LrpcCallDone(uint Status, ReadOnlySpan<byte> Response);

    // A client of a guest rpcrt4 server. It binds NDR 2.0 only, sends no views, and calls back like AlpcHost.
    internal sealed class LrpcClient
    {
        // rpcrt4 LRPC_BASE_CCALL::GetBuffer puts a larger stub in a view.
        private const int MaxStubLength = 0xF98;

        private readonly BinaryEmulator Instance;
        private readonly AlpcConnection Connection;
        private readonly uint AssociationTick;
        private ushort NextContext;
        private uint NextCallId;

        private LrpcClient(BinaryEmulator Instance, AlpcConnection Connection)
        {
            this.Instance = Instance;
            this.Connection = Connection;
            AssociationTick = (uint)Instance.EmulatedTickCount64;
        }

        // An endpoint that starts with a backslash is a full port path, as AppContainer servers use.
        internal static string GetPortName(string Endpoint)
        {
            string Name = Endpoint.Contains('\\') ? Unescape(Endpoint) : Endpoint;
            return Name.StartsWith('\\') ? Name : "\\RPC Control\\" + Name;
        }

        private static string Unescape(string Endpoint)
        {
            Span<char> Name = Endpoint.Length <= 256 ? stackalloc char[Endpoint.Length] : new char[Endpoint.Length];
            int Length = 0;
            int Index = 0;
            while (Index < Endpoint.Length)
            {
                if (Endpoint[Index] == '\\' && Index + 1 < Endpoint.Length)
                    Index++;
                Name[Length++] = Endpoint[Index++];
            }

            return new string(Name.Slice(0, Length));
        }

        internal static uint Connect(BinaryEmulator Instance, string PortName, ulong ProcessId, ulong ThreadId, WinToken Token, SecurityImpersonationLevel Level,
            Action<uint> Connected, out LrpcClient Client)
        {
            Client = null;
            WinPort Port = NtConnectPort.FindPortByName(Instance, PortName);
            if (Port?.Queue == null)
                return LrpcPacket.RpcSServerUnavailable;

            AlpcHost Host = new AlpcHost
            {
                ProcessId = ProcessId,
                ThreadId = ThreadId,
                Connected = Status => Connected(Status == NTSTATUS.STATUS_SUCCESS ? LrpcPacket.RpcOk : LrpcPacket.RpcSServerUnavailable),
            };

            AlpcSecurityContext Identity = new AlpcSecurityContext { Token = Token, Qos = new SecurityQos(Level, DynamicTracking: false, EffectiveOnly: false) };
            if (AlpcMessaging.ConnectHost(Instance, Port, Host, Identity, out AlpcConnection Connection) != NTSTATUS.STATUS_SUCCESS)
                return LrpcPacket.RpcSServerUnavailable;

            Client = new LrpcClient(Instance, Connection);
            return LrpcPacket.RpcOk;
        }

        // Bound gets the status and the presentation context that Call takes.
        internal uint Bind(Guid Interface, Action<uint, ushort> Bound)
        {
            ushort Context = NextContext++;
            byte[] Payload = LrpcPacket.BuildBindPayload(Interface, Context, AssociationTick);
            return Send(Payload, (Status, Answer) => Bound(Status == NTSTATUS.STATUS_SUCCESS ? LrpcPacket.ParseBindAnswer(Answer) : LrpcPacket.RpcSCallFailedDne, Context));
        }

        internal uint Call(ushort Context, uint ProcNumber, Guid ObjectId, ReadOnlySpan<byte> StubData, LrpcCallDone Done)
        {
            if (StubData.Length > MaxStubLength)
                return LrpcPacket.RpcSCannotSupport;

            uint CallId = ++NextCallId;
            byte[] Payload = LrpcPacket.BuildRequestPayload(CallId, Context, ProcNumber, ObjectId, StubData);
            return Send(Payload, (Status, Answer) =>
            {
                uint Result = Status == NTSTATUS.STATUS_SUCCESS ? LrpcPacket.ParseResponse(Answer, CallId) : LrpcPacket.RpcSCallFailedDne;
                Done(Result, Result == LrpcPacket.RpcOk ? Answer.Slice(LrpcPacket.ResponsePayloadStubOffset) : default);
            });
        }

        // Binds and calls still waiting end with RPC_S_CALL_FAILED_DNE.
        internal void Close()
        {
            AlpcMessaging.CloseClient(Instance, Connection);
        }

        private uint Send(byte[] Payload, HostReplyHandler OnAnswer)
        {
            return AlpcMessaging.SendHost(Instance, Connection, Payload, OnAnswer) == NTSTATUS.STATUS_SUCCESS ? LrpcPacket.RpcOk : LrpcPacket.RpcSCallFailedDne;
        }
    }
}
