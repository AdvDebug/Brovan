using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

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
        private const ushort RegisterObjectMethod = 11;
        private const ushort UnregisterObjectMethod = 13;
        private const ushort RegisterPortMethod = 14;
        private const ushort UnregisterPortMethod = 15;
        private const ushort ReleaseConversationClientMethod = 22;
        private const ushort RegisterConversationClientMethod = 23;
        private const ushort ReplyRegisterThreadMethod = 4;
        private const ushort ReplyRegisterObjectMethod = 14;
        private const ushort ReplyUnregisterObjectMethod = 16;
        private const ushort ReplyRegisterPortMethod = 17;
        private const ushort ReplyUnregisterPortMethod = 18;
        private const ushort ReplyReleaseConversationClientMethod = 28;
        private const ushort ReplyRegisterConversationClientMethod = 29;
        private const uint MessagingSuccess = 0;
        private const uint MessagingDuplicateName = 3;
        private const uint MessagingObjectNotFound = 9;
        private const uint MessagingTooManyConversationClients = 17;

        // NT: AlpcAdapter::ValidateString.
        private const int MaxNameLength = 512;

        // ScopeID {u32 kind, u32 process id for the process scope, Guid}.
        private const int ScopeIdSize = 0x18;
        private const uint SessionScope = 1;
        private const uint ProcessScope = 2;
        private const int HIdentitySize = 8;
        private const uint ObjectTypeCount = 2;
        // NT: RegisteredObjectValidator::ValidateRegisteredObjectParams counts the registrations of a process.
        private const int MaxProcessRegistrations = 0x400;
        private const string ReservedKernelPrefix = "Kernel\\";

        // NT: RegisteredConversation::CreateClient counts the conversation clients of a process.
        private const int MaxConversationClients = 0x2800;
        // NT: RegisteredConversation::s_lastHint goes back to 1 past this.
        private const uint MaxConversationHint = 0xFFFF;
        // ConversationInfo {hint, item owner, server style, connection mode}.
        private const int ConversationInfoSize = 16;

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

        private readonly record struct ObjectKey(uint Type, string Name);

        private readonly record struct ConversationPeer(Conversation Conversation, uint PeerId);

        private sealed class Client
        {
            internal ulong ClientId;
            internal readonly HashSet<Guid> Ports = new HashSet<Guid>();
            internal readonly HashSet<ObjectKey> Objects = new HashSet<ObjectKey>();
            internal readonly HashSet<ConversationPeer> ConversationPeers = new HashSet<ConversationPeer>();
        }

        private sealed class Conversation
        {
            internal uint Hint;
            internal uint ItemOwner;
            internal uint ServerStyle;
            internal uint ConnectionMode;
            internal PeerIds Peers;
            internal readonly Dictionary<uint, Client> Clients = new Dictionary<uint, Client>();
        }

        // NT: IDLRUAllocator. ID 0 is reserved, a new ID is the lowest free one, and a released ID is free again
        // only after 128 later releases.
        private sealed class PeerIds
        {
            private const int RetiredCapacity = 128;

            private readonly SortedSet<uint> Free = new SortedSet<uint>();
            private readonly Queue<uint> Retired = new Queue<uint>();
            private uint Next = 1;

            internal uint Allocate()
            {
                if (Free.Count == 0)
                    return Next++;

                uint Id = Free.Min;
                Free.Remove(Id);
                return Id;
            }

            internal void Release(uint Id)
            {
                Retired.Enqueue(Id);
                if (Retired.Count > RetiredCapacity)
                    Free.Add(Retired.Dequeue());
            }
        }

        private readonly Dictionary<AlpcConnection, Client> Clients = new Dictionary<AlpcConnection, Client>();
        // The process scope of the one guest process the registrar serves, with the thread that registered each name.
        private readonly Dictionary<ObjectKey, Client> ProcessObjects = new Dictionary<ObjectKey, Client>();
        // The session scope as the one guest process sees it. Peer IDs are shared by the conversations of one eager name.
        private readonly Dictionary<string, Conversation> SessionConversations = new Dictionary<string, Conversation>(StringComparer.Ordinal);
        private readonly Dictionary<string, PeerIds> SessionPeerIds = new Dictionary<string, PeerIds>(StringComparer.Ordinal);
        private ulong NextClientId;
        private uint NextGroup;
        private int Registrations;
        private uint LastConversationHint;
        private ulong LastConversationUniqueId;
        private int ConversationClients;

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
            if (!Clients.TryGetValue(Connection, out Client State)
                || !TryReadCall(Data, WaitsForReply, out ushort Method, out uint Sequence, out CallReader Parameters))
            {
                Utils.LogError($"[-] CoreMessaging registrar: a client sent a message of {Data.Length} bytes that is not a single registrar call.");
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            switch (Method)
            {
                case RegisterThreadMethod:
                    return RegisterThread(State, ref Parameters, Sequence, out Reply);
                case RegisterObjectMethod:
                    return RegisterObject(Instance, State, ref Parameters, Sequence, out Reply);
                case UnregisterObjectMethod:
                    return UnregisterObject(Instance, State, ref Parameters, Sequence, out Reply);
                case RegisterPortMethod:
                    return RegisterPort(State, ref Parameters, Sequence, out Reply);
                case UnregisterPortMethod:
                    return UnregisterPort(State, ref Parameters, Sequence, out Reply);
                case ReleaseConversationClientMethod:
                    return ReleaseConversationClient(State, ref Parameters, Sequence, out Reply);
                case RegisterConversationClientMethod:
                    return RegisterConversationClient(State, ref Parameters, Sequence, out Reply);
                default:
                    Utils.LogError($"[-] CoreMessaging registrar: {RegistrarMethods[Method]} is not served.");
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }
        }

        internal override void Disconnected(BinaryEmulator Instance, AlpcConnection Connection)
        {
            if (!Clients.Remove(Connection, out Client State))
                return;

            Registrations -= State.Ports.Count;
            foreach (ObjectKey Key in State.Objects)
                ProcessObjects.Remove(Key);

            foreach (ConversationPeer Peer in State.ConversationPeers)
                ForgetConversationClient(Peer.Conversation, Peer.PeerId);
        }

        // NT: RemoteRegistrarServer::RegisterThread reserves a group of the client process for the thread.
        private NTSTATUS RegisterThread(Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.AtEnd)
                return Malformed(RegisterThreadMethod);

            Span<byte> VmId = stackalloc byte[16];
            VmId.Clear();
            CallWriter Call = new CallWriter(ClientInterface, ReplyRegisterThreadMethod);
            Call.UInt32(MessagingSuccess);
            Call.UInt64(State.ClientId);
            Call.Bytes(VmId);
            Call.UInt32(++NextGroup);
            Reply = Call.ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: RemoteRegistrarServer::RegisterObject. Only the process scope is served.
        private NTSTATUS RegisterObject(BinaryEmulator Instance, Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadFixed(HIdentitySize, out _) || !Parameters.TryReadGuid(out Guid ObjectId)
                || !Parameters.TryReadUInt32(out uint Type) || !Parameters.AtEnd)
                return Malformed(RegisterObjectMethod);

            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            if ((ScopeKind != 0 && ObjectId == Guid.Empty) || Type >= ObjectTypeCount || !IsValidName(Name))
                return ProtocolError(RegisterObjectMethod);

            if (ScopeKind != ProcessScope)
                return ScopeNotServed(RegisterObjectMethod, ScopeKind);

            if (!IsOwnProcessScope(Instance, Scope) || Name.StartsWith(ReservedKernelPrefix, StringComparison.Ordinal)
                || ProcessObjects.Count >= MaxProcessRegistrations)
                return ProtocolError(RegisterObjectMethod);

            ObjectKey Key = new ObjectKey(Type, Name.ToString());
            uint Result = MessagingDuplicateName;
            if (ProcessObjects.TryAdd(Key, State))
            {
                State.Objects.Add(Key);
                Result = MessagingSuccess;
            }

            CallWriter Call = new CallWriter(ClientInterface, ReplyRegisterObjectMethod);
            Call.UInt32(Result);
            Reply = Call.ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: RegistrationNameMaps::CleanupRegistrationCommon finds the name only among those of the calling thread.
        private NTSTATUS UnregisterObject(BinaryEmulator Instance, Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadUInt32(out uint Type) || !Parameters.AtEnd)
                return Malformed(UnregisterObjectMethod);

            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            if (Type >= ObjectTypeCount || !IsValidName(Name))
                return ProtocolError(UnregisterObjectMethod);

            if (ScopeKind != ProcessScope)
                return ScopeNotServed(UnregisterObjectMethod, ScopeKind);

            if (!IsOwnProcessScope(Instance, Scope))
                return ProtocolError(UnregisterObjectMethod);

            ObjectKey Key = new ObjectKey(Type, Name.ToString());
            uint Result = MessagingObjectNotFound;
            if (State.Objects.Remove(Key))
            {
                ProcessObjects.Remove(Key);
                Result = MessagingSuccess;
            }

            CallWriter Call = new CallWriter(ClientInterface, ReplyUnregisterObjectMethod);
            Call.UInt32(Result);
            Reply = Call.ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsValidName(ReadOnlySpan<char> Name) => !Name.IsEmpty && Name.Length <= MaxNameLength;

        // NT: RegisteredObjectValidator::ValidateRegistrarScope. A process scope names the caller's process or 0.
        private static bool IsOwnProcessScope(BinaryEmulator Instance, ReadOnlySpan<byte> Scope)
        {
            uint ProcessId = BinaryPrimitives.ReadUInt32LittleEndian(Scope.Slice(4));
            return ProcessId == 0 || ProcessId == Instance.WinHelper.PID;
        }

        // NT: RemoteRegistrarServer::RegisterPort. The ports belong to the thread of the connection.
        private NTSTATUS RegisterPort(Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadGuid(out Guid PortId) || !Parameters.TryReadString(out ReadOnlySpan<char> Name)
                || !Parameters.TryReadGuid(out _) || !Parameters.AtEnd)
                return Malformed(RegisterPortMethod);

            if (!IsValidName(Name) || State.Ports.Contains(PortId))
                return ProtocolError(RegisterPortMethod);

            if (Registrations >= MemoryBudget.CoreMessagingRegistrations)
            {
                Utils.LogError($"[-] CoreMessaging registrar: refused a port past the limit of {MemoryBudget.CoreMessagingRegistrations} registrations.");
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
            }

            State.Ports.Add(PortId);
            Registrations++;
            Reply = new CallWriter(ClientInterface, ReplyRegisterPortMethod).ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS UnregisterPort(Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadGuid(out Guid PortId) || !Parameters.AtEnd)
                return Malformed(UnregisterPortMethod);

            if (!State.Ports.Remove(PortId))
                return ProtocolError(UnregisterPortMethod);

            Registrations--;
            Reply = new CallWriter(ClientInterface, ReplyUnregisterPortMethod).ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: ServerConversationOperations::RegisterConversationClient. With no conversation of that name, an eager
        // client creates one, and a server that registers later is announced to it.
        private NTSTATUS RegisterConversationClient(Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadUInt32(out uint ConnectionMode) || !Parameters.TryReadBool(out bool Eager)
                || !Parameters.TryReadString(out ReadOnlySpan<char> EagerName) || !Parameters.TryReadUInt32(out uint ItemOwner)
                || !Parameters.TryReadUInt32(out uint ServerStyle) || !Parameters.AtEnd)
                return Malformed(RegisterConversationClientMethod);

            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            if (!IsValidName(Name))
                return ProtocolError(RegisterConversationClientMethod);

            if (ScopeKind != SessionScope)
                return ScopeNotServed(RegisterConversationClientMethod, ScopeKind);

            if (!IsCallerSessionScope(Scope) || Name.StartsWith(ReservedKernelPrefix, StringComparison.Ordinal)
                || ProcessObjects.Count >= MaxProcessRegistrations)
                return ProtocolError(RegisterConversationClientMethod);

            // NT: an eager conversation takes only eager clients, and no server registers a conversation here.
            if (!Eager)
                return ConversationClientReply(MessagingObjectNotFound, 0, 0, null, Sequence, out Reply);

            if (ConversationClients >= MaxConversationClients)
                return ConversationClientReply(MessagingTooManyConversationClients, 0, 0, null, Sequence, out Reply);

            string Key = Name.ToString();
            if (!SessionConversations.TryGetValue(Key, out Conversation Conversation))
            {
                if (!IsValidName(EagerName) || EagerName.StartsWith(ReservedKernelPrefix, StringComparison.Ordinal))
                    return ProtocolError(RegisterConversationClientMethod);

                if (Registrations >= MemoryBudget.CoreMessagingRegistrations)
                {
                    Utils.LogError($"[-] CoreMessaging registrar: refused a conversation past the limit of {MemoryBudget.CoreMessagingRegistrations} registrations.");
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                }

                string PeerKey = EagerName.ToString();
                if (!SessionPeerIds.TryGetValue(PeerKey, out PeerIds Peers))
                {
                    Peers = new PeerIds();
                    SessionPeerIds.Add(PeerKey, Peers);
                }

                LastConversationHint = LastConversationHint >= MaxConversationHint ? 1 : LastConversationHint + 1;
                Conversation = new Conversation
                {
                    Hint = LastConversationHint,
                    ItemOwner = ItemOwner,
                    ServerStyle = ServerStyle,
                    ConnectionMode = ConnectionMode,
                    Peers = Peers,
                };
                SessionConversations.Add(Key, Conversation);
                Registrations++;
            }

            uint PeerId = Conversation.Peers.Allocate();
            Conversation.Clients.Add(PeerId, State);
            State.ConversationPeers.Add(new ConversationPeer(Conversation, PeerId));
            ConversationClients++;
            return ConversationClientReply(MessagingSuccess, PeerId, ++LastConversationUniqueId, Conversation, Sequence, out Reply);
        }

        private static NTSTATUS ConversationClientReply(uint Result, uint PeerId, ulong UniqueId, Conversation Conversation, uint Sequence, out byte[] Reply)
        {
            Span<byte> Info = stackalloc byte[ConversationInfoSize];
            Info.Clear();
            if (Conversation != null)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Info, Conversation.Hint);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(4), Conversation.ItemOwner);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(8), Conversation.ServerStyle);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(12), Conversation.ConnectionMode);
            }

            CallWriter Call = new CallWriter(ClientInterface, ReplyRegisterConversationClientMethod);
            Call.UInt32(Result);
            Call.UInt32(PeerId);
            Call.UInt64(UniqueId);
            Call.Bytes(Info);
            // The server peers of the conversation, which no server joins here.
            Call.Bytes(ReadOnlySpan<byte>.Empty);
            Reply = Call.ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: ServerConversationOperations::ReleaseConversationClient. A name with no conversation still gets the reply.
        private NTSTATUS ReleaseConversationClient(Client State, ref CallReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadUInt32(out uint PeerId) || !Parameters.AtEnd)
                return Malformed(ReleaseConversationClientMethod);

            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            if (!IsValidName(Name))
                return ProtocolError(ReleaseConversationClientMethod);

            if (ScopeKind != SessionScope)
                return ScopeNotServed(ReleaseConversationClientMethod, ScopeKind);

            if (!IsCallerSessionScope(Scope))
                return ProtocolError(ReleaseConversationClientMethod);

            if (SessionConversations.TryGetValue(Name.ToString(), out Conversation Conversation))
            {
                // NT: RegisteredConversation::TryGetClient finds only the clients of the calling thread.
                if (!Conversation.Clients.TryGetValue(PeerId, out Client Owner) || Owner != State)
                    return ProtocolError(ReleaseConversationClientMethod);

                State.ConversationPeers.Remove(new ConversationPeer(Conversation, PeerId));
                ForgetConversationClient(Conversation, PeerId);
            }

            Reply = new CallWriter(ClientInterface, ReplyReleaseConversationClientMethod).ToReply(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private void ForgetConversationClient(Conversation Conversation, uint PeerId)
        {
            Conversation.Clients.Remove(PeerId);
            Conversation.Peers.Release(PeerId);
            ConversationClients--;
        }

        // NT: RegisteredObjectValidator::ValidateRegistrarScope. A session scope names no process and no partition.
        private static bool IsCallerSessionScope(ReadOnlySpan<byte> Scope)
            => BinaryPrimitives.ReadUInt32LittleEndian(Scope.Slice(4)) == 0 && !Scope.Slice(8).ContainsAnyExcept((byte)0);

        private static NTSTATUS Malformed(ushort Method)
        {
            Utils.LogError($"[-] CoreMessaging registrar: the parameters of a {RegistrarMethods[Method]} call do not match its format.");
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // NT answers with a protocol exception message and drops the connection, which Brovan does not model.
        private static NTSTATUS ProtocolError(ushort Method)
        {
            Utils.LogError($"[-] CoreMessaging registrar: refused a {RegistrarMethods[Method]} call that breaks the registrar protocol.");
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static NTSTATUS ScopeNotServed(ushort Method, uint ScopeKind)
        {
            Utils.LogError($"[-] CoreMessaging registrar: {RegistrarMethods[Method]} in scope kind {ScopeKind} is not served.");
            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        // The checks follow AlpcConnection::ValidateBufferHeader in coremessaging. Chunked and batched calls are refused.
        private static bool TryReadCall(ReadOnlySpan<byte> Data, bool WaitsForReply, out ushort Method, out uint Sequence, out CallReader Parameters)
        {
            Method = 0;
            Sequence = 0;
            Parameters = default;
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
            Sequence = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(OffSequence));
            Parameters = new CallReader(Call.Slice(CallHeaderSize));
            return (ulong)SizeInDwords * 4 == PayloadLength && Interface == RegistrarInterface && Method < RegistrarMethods.Length;
        }

        // NT: ReceiveProcessor::UnmarshalReceive. Each parameter is a u32 size and its bytes padded to 4, and the
        // parameters fill the call exactly.
        private ref struct CallReader
        {
            private ReadOnlySpan<byte> Remaining;

            internal CallReader(ReadOnlySpan<byte> Parameters) => Remaining = Parameters;

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

            private bool TryReadNext(out ReadOnlySpan<byte> Value)
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

            // NT: AlpcServerConnection::PostSynchronousCallResponse gives the reply the sequence of its request.
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
