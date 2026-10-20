using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The CoreMessagingRegistrar service in coremessaging.dll, which marshals its calls with CoreUICallSend.
    internal sealed class CoreMessagingRegistrarPort : AlpcHostServer
    {
        internal const string PortName = "\\BaseNamedObjects\\CoreMessagingRegistrar";

        private const int ConnectDataSize = 0x18;
        private static readonly Guid ConnectProtocol = new Guid("20d782ff-8896-4c1e-8eae-b630f3543dd1");

        private const int BufferHeaderSize = 0x28;
        private const int OffReservedZero = 0x00;
        private const int OffKind = 0x10;
        private const int OffSequence = 0x14;
        private const int OffBatchIndex = 0x18;
        private const int OffBatchCount = 0x1A;
        private const int OffPayloadLength = 0x20;
        private const uint KindMask = 0x27;
        private const uint KindChunked = 0x10;
        private const uint KindRequest = 2;

        private const int CallHeaderSize = 8;
        private const ushort RegistrarInterface = 1;
        private const ushort ClientInterface = 0;
        private const ushort RegisterThreadMethod = 1;
        private const ushort ReplyRegisterThreadMethod = 4;
        private const uint MessagingSuccess = 0;

        // IRegistrarServer, in method order (IRegistrarServer_Receive::Type in coremessaging.dll).
        private static readonly string[] RegistrarMethods =
        {
            "ConnectContainerThread", "RegisterThread", "LookupCrossPartitionClient", "PrepareConnection",
            "CompleteCrossProcConnection", "CompleteLocalConnection", "CloseConnection", "LocalClientDisconnected",
            "CrossProcClientDisconnected", "ContainerThreadDisconnected", "GetExtendedInformation", "RegisterObject",
            "FindObject", "UnregisterObject", "RegisterPort", "UnregisterPort", "GetOrCreateReverseConnectionPortID",
            "UnregisterReverseConnectionPort", "FindCrossProcConnection", "FreeServerGroupIDForClient",
            "RegisterConversation", "ReleaseConversationServer", "ReleaseConversationClient", "RegisterConversationClient",
            "RegisterPendingConversationClientForServer", "ReleaseConversationClientConnection",
            "FindPendingConversationClient", "ConnectPendingConversationClient", "ClientConversationAttached",
        };

        private sealed class Client
        {
            internal ulong ClientId;
            internal uint NextSequence;
        }

        private readonly Dictionary<AlpcConnection, Client> Clients = new Dictionary<AlpcConnection, Client>();
        private ulong NextClientId;
        private uint NextGroup;

        internal override bool Connect(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, out byte[] Reply)
        {
            Reply = null;
            if (Data.Length != ConnectDataSize || new Guid(Data.Slice(0, 16)) != ConnectProtocol)
            {
                Utils.LogError($"[-] CoreMessaging registrar: refused a connect message of {Data.Length} bytes.");
                return false;
            }

            Clients[Connection] = new Client { ClientId = ++NextClientId };
            Reply = Data.ToArray();
            return true;
        }

        internal override NTSTATUS Receive(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, bool WaitsForReply, out byte[] Reply)
        {
            Reply = null;
            if (!Clients.TryGetValue(Connection, out Client State) || !TryReadCall(Data, WaitsForReply, out ushort Method))
            {
                Utils.LogError($"[-] CoreMessaging registrar: a client sent a message of {Data.Length} bytes that is not a single registrar call.");
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (Method != RegisterThreadMethod)
            {
                Utils.LogError($"[-] CoreMessaging registrar: {RegistrarMethods[Method]} is not served.");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            // NT: RemoteRegistrarServer::RegisterThread reserves a group of the client process for the thread.
            Span<byte> VmId = stackalloc byte[16];
            VmId.Clear();
            CallWriter Call = new CallWriter(ClientInterface, ReplyRegisterThreadMethod);
            Call.UInt32(MessagingSuccess);
            Call.UInt64(State.ClientId);
            Call.Bytes(VmId);
            Call.UInt32(++NextGroup);
            Reply = Call.ToReply(State.NextSequence++);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal override void Disconnected(BinaryEmulator Instance, AlpcConnection Connection)
        {
            Clients.Remove(Connection);
        }

        // The checks follow AlpcConnection::ValidateBufferHeader in coremessaging. Chunked and batched calls are refused.
        private static bool TryReadCall(ReadOnlySpan<byte> Data, bool WaitsForReply, out ushort Method)
        {
            Method = 0;
            if (Data.Length < BufferHeaderSize + CallHeaderSize)
                return false;

            uint Kind = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(OffKind));
            uint PayloadLength = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(OffPayloadLength));
            if (BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(OffReservedZero)) != 0
                || PayloadLength != (uint)(Data.Length - BufferHeaderSize)
                || (Kind & KindChunked) != 0 || (Kind & KindMask) != KindRequest || !WaitsForReply
                || BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(OffBatchIndex)) != 0
                || BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(OffBatchCount)) != 1)
                return false;

            ReadOnlySpan<byte> Call = Data.Slice(BufferHeaderSize);
            uint SizeInDwords = BinaryPrimitives.ReadUInt32LittleEndian(Call);
            ushort Interface = BinaryPrimitives.ReadUInt16LittleEndian(Call.Slice(4));
            Method = BinaryPrimitives.ReadUInt16LittleEndian(Call.Slice(6));
            return (ulong)SizeInDwords * 4 == PayloadLength && Interface == RegistrarInterface && Method < RegistrarMethods.Length;
        }

        private readonly struct CallWriter
        {
            private static readonly byte[] Padding = new byte[3];

            private readonly ushort Interface;
            private readonly ushort Method;
            private readonly ArrayBufferWriter<byte> Parameters;

            internal CallWriter(ushort Interface, ushort Method)
            {
                this.Interface = Interface;
                this.Method = Method;
                Parameters = new ArrayBufferWriter<byte>(0x40);
            }

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

            internal void Bytes(ReadOnlySpan<byte> Value)
            {
                Span<byte> Size = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(Size, (uint)Value.Length);
                Parameters.Write(Size);
                Parameters.Write(Value);
                Parameters.Write(Padding.AsSpan(0, -Value.Length & 3));
            }

            internal byte[] ToReply(uint Sequence)
            {
                int PayloadLength = CallHeaderSize + Parameters.WrittenCount;
                byte[] Reply = new byte[BufferHeaderSize + PayloadLength];
                Span<byte> Header = Reply;
                BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(OffSequence), Sequence);
                BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(OffBatchCount), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(OffPayloadLength), (uint)PayloadLength);

                Span<byte> Call = Header.Slice(BufferHeaderSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Call, (uint)(PayloadLength / 4));
                BinaryPrimitives.WriteUInt16LittleEndian(Call.Slice(4), Interface);
                BinaryPrimitives.WriteUInt16LittleEndian(Call.Slice(6), Method);
                Parameters.WrittenSpan.CopyTo(Call.Slice(CallHeaderSize));
                return Reply;
            }
        }
    }
}
