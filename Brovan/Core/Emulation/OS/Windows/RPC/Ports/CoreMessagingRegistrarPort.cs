using System;
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

        private const ushort RegistrarInterface = 1;
        private const ushort ClientInterface = 0;
        private const ushort RegisterThreadMethod = 1;
        private const ushort PrepareConnectionMethod = 3;
        private const ushort CloseConnectionMethod = 6;
        private const ushort GetExtendedInformationMethod = 10;
        private const ushort RegisterObjectMethod = 11;
        private const ushort FindObjectMethod = 12;
        private const ushort UnregisterObjectMethod = 13;
        private const ushort RegisterPortMethod = 14;
        private const ushort UnregisterPortMethod = 15;
        private const ushort GetOrCreateReverseConnectionPortIdMethod = 16;
        private const ushort UnregisterReverseConnectionPortMethod = 17;
        private const ushort ReleaseConversationClientMethod = 22;
        private const ushort RegisterConversationClientMethod = 23;
        private const ushort ReplyRegisterThreadMethod = 4;
        private const ushort ReplyPrepareConnectionMethod = 6;
        private const ushort ReplyCloseConnectionMethod = 9;
        private const ushort ReplyGetExtendedInformationMethod = 13;
        private const ushort ReplyRegisterObjectMethod = 14;
        private const ushort ReplyFindObjectMethod = 15;
        private const ushort ReplyUnregisterObjectMethod = 16;
        private const ushort ReplyRegisterPortMethod = 17;
        private const ushort ReplyUnregisterPortMethod = 18;
        private const ushort ReplyGetOrCreateReverseConnectionPortIdMethod = 19;
        private const ushort ReplyUnregisterReverseConnectionPortMethod = 20;
        private const ushort ReplyReleaseConversationClientMethod = 28;
        private const ushort ReplyRegisterConversationClientMethod = 29;
        internal const uint MessagingSuccess = 0;
        private const uint MessagingDuplicateName = 3;
        private const uint MessagingClientNotFound = 5;
        private const uint MessagingObjectNotFound = 9;
        private const uint MessagingNoMoreIds = 10;
        private const uint MessagingTooManyConversationClients = 17;

        // NT: AlpcAdapter::ValidateString.
        private const int MaxNameLength = 512;

        // ScopeID {u32 kind, u32 process id for the process scope, Guid}.
        private const int ScopeIdSize = 0x18;
        internal const uint SessionScope = 1;
        private const uint ProcessScope = 2;
        private const uint ObjectTypeCount = 2;
        // NT: RegisteredObjectValidator::ValidateRegisteredObjectParams counts the registrations of a process.
        private const int MaxProcessRegistrations = 0x400;
        private const string ReservedKernelPrefix = "Kernel\\";

        private const int PendingConnectionSize = 0x38;
        private const int OffPendingIdentity0 = 0x08;
        private const int OffPendingServerClient = 0x10;
        private const int OffPendingPort = 0x18;
        private const int OffPendingClientGroup = 0x28;
        private const int OffPendingServerGroup = 0x2C;
        private const int OffPendingIdentity1 = 0x30;

        // NT hands out groups 1 to 0x3FFFF of a process (RegistrarProcessContext::ReserveGroup).
        private const uint MaxGroups = 0x40000;

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

        internal readonly record struct ObjectKey(uint Scope, uint Type, string Name);

        private readonly record struct RegisteredObject(Client Owner, ulong Identity, Guid Port);

        internal readonly record struct ConversationPeer(Conversation Conversation, uint PeerId);

        internal sealed class Client
        {
            internal ulong ClientId { get; init; }
            internal uint ProcessId { get; init; }
            internal uint ThreadId { get; init; }
            // RegisterThread keeps the earlier groups, and the newest one holds the session identities.
            internal readonly List<uint> Groups = new List<uint>();
            internal readonly Dictionary<Guid, string> Ports = new Dictionary<Guid, string>();
            internal readonly HashSet<ObjectKey> Objects = new HashSet<ObjectKey>();
            internal readonly HashSet<ConversationPeer> ConversationPeers = new HashSet<ConversationPeer>();
            internal readonly Dictionary<Guid, Guid> ReverseConnectionPortIds = new Dictionary<Guid, Guid>();
            internal readonly Dictionary<Guid, Guid> ReverseConnectionPortKeys = new Dictionary<Guid, Guid>();
            internal readonly List<RegistrarConnection> Connections = new List<RegistrarConnection>();

            internal uint Group => Groups.Count != 0 ? Groups[^1] : 0;

            internal void WriteRoutingInfo(Span<byte> Routing, ulong Identity, Guid Port)
                => CoreMessagingRouting.Write(Routing, ProcessId, ThreadId, Identity, ClientId, Port);

            internal bool IsNamedBy(ReadOnlySpan<byte> Routing)
                => CoreMessagingRouting.ProcessId(Routing) == ProcessId && CoreMessagingRouting.ThreadId(Routing) == ThreadId;
        }

        internal sealed class RegistrarConnection
        {
            internal Client ClientThread { get; init; }
            internal Client Server { get; init; }
            internal Guid Port { get; init; }
            internal uint ClientGroup { get; init; }
            internal uint ServerGroup { get; init; }
            // Once a host server accepts, only the end of that server connection releases the record.
            internal bool Accepted;
        }

        internal sealed class Conversation
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
        internal sealed class PeerIds
        {
            private const int RetiredCapacity = 128;

            private readonly LowestFreeIds Ids = new LowestFreeIds(1, uint.MaxValue);
            private readonly Queue<uint> Retired = new Queue<uint>();

            internal uint Allocate()
            {
                Ids.TryTake(out uint Id);
                return Id;
            }

            internal void Release(uint Id)
            {
                Retired.Enqueue(Id);
                if (Retired.Count > RetiredCapacity)
                    Ids.Release(Retired.Dequeue());
            }
        }

        private readonly Dictionary<ulong, Client> Clients = new Dictionary<ulong, Client>();
        private readonly Dictionary<uint, LowestFreeIds> GroupPools = new Dictionary<uint, LowestFreeIds>();
        private readonly CoreMessagingWriter ReplyWriter = new CoreMessagingWriter();
        // The process scope of the one guest process the registrar serves.
        private readonly Dictionary<ObjectKey, RegisteredObject> ProcessObjects = new Dictionary<ObjectKey, RegisteredObject>();
        private readonly Dictionary<ObjectKey, RegisteredObject> SessionObjects = new Dictionary<ObjectKey, RegisteredObject>();
        // The session scope as the one guest process sees it. Peer IDs are shared by the conversations of one eager name.
        private readonly Dictionary<string, Conversation> SessionConversations = new Dictionary<string, Conversation>(StringComparer.Ordinal);
        private readonly Dictionary<string, PeerIds> SessionPeerIds = new Dictionary<string, PeerIds>(StringComparer.Ordinal);
        private ulong NextClientId;
        private int Registrations;
        private uint LastConversationHint;
        private ulong LastConversationUniqueId;
        private int ConversationClients;

        internal override bool Connect(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, out byte[] Reply, out object State)
        {
            Reply = null;
            State = null;
            if (Data.Length != ConnectDataSize || new Guid(Data.Slice(0, 16)) != ConnectProtocol)
            {
                Utils.LogError($"[-] CoreMessaging registrar: refused a connect message of {Data.Length} bytes.");
                return false;
            }

            Client Caller = new Client { ClientId = ++NextClientId, ProcessId = Instance.WinHelper.PID, ThreadId = (uint)Instance.CurrentThreadId };
            Clients.Add(Caller.ClientId, Caller);
            State = Caller;
            Reply = Data.ToArray();
            return true;
        }

        internal override NTSTATUS Receive(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, bool WaitsForReply, out byte[] Reply)
        {
            Reply = null;
            if (Connection.HostServerState is not Client Caller
                || !CoreMessagingBuffer.TryRead(Data, out CoreMessagingBuffer Header, out ReadOnlySpan<byte> Payload)
                || Header.Kind != CoreMessagingBuffer.KindCall || !WaitsForReply
                || !CoreMessagingCall.TryRead(Payload, out ushort Interface, out ushort Method, out CoreMessagingReader Parameters)
                || Interface != RegistrarInterface || Method >= RegistrarMethods.Length)
            {
                Utils.LogError($"[-] CoreMessaging registrar: a client sent a message of {Data.Length} bytes that is not a single registrar call.");
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            uint Sequence = Header.Sequence;
            switch (Method)
            {
                case RegisterThreadMethod:
                    return RegisterThread(Caller, ref Parameters, Sequence, out Reply);
                case PrepareConnectionMethod:
                    return PrepareConnection(Caller, ref Parameters, Sequence, out Reply);
                case CloseConnectionMethod:
                    return CloseConnection(Caller, ref Parameters, Sequence, out Reply);
                case GetExtendedInformationMethod:
                    return GetExtendedInformation(ref Parameters, Sequence, out Reply);
                case RegisterObjectMethod:
                    return RegisterObject(Instance, Caller, ref Parameters, Sequence, out Reply);
                case FindObjectMethod:
                    return FindObject(Instance, ref Parameters, Sequence, out Reply);
                case UnregisterObjectMethod:
                    return UnregisterObject(Instance, Caller, ref Parameters, Sequence, out Reply);
                case RegisterPortMethod:
                    return RegisterPort(Caller, ref Parameters, Sequence, out Reply);
                case UnregisterPortMethod:
                    return UnregisterPort(Caller, ref Parameters, Sequence, out Reply);
                case GetOrCreateReverseConnectionPortIdMethod:
                    return GetOrCreateReverseConnectionPortId(Caller, ref Parameters, Sequence, out Reply);
                case UnregisterReverseConnectionPortMethod:
                    return UnregisterReverseConnectionPort(Caller, ref Parameters, Sequence, out Reply);
                case ReleaseConversationClientMethod:
                    return ReleaseConversationClient(Caller, ref Parameters, Sequence, out Reply);
                case RegisterConversationClientMethod:
                    return RegisterConversationClient(Caller, ref Parameters, Sequence, out Reply);
                default:
                    Utils.LogError($"[-] CoreMessaging registrar: {RegistrarMethods[Method]} is not served.");
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }
        }

        internal override void Disconnected(BinaryEmulator Instance, AlpcConnection Connection)
        {
            if (Connection.HostServerState is not Client Caller || !Clients.Remove(Caller.ClientId))
                return;

            Registrations -= Caller.Ports.Count + Caller.ReverseConnectionPortIds.Count;
            foreach (ObjectKey Key in Caller.Objects)
                ForgetObject(Key);

            foreach (ConversationPeer Peer in Caller.ConversationPeers)
                ForgetConversationClient(Peer.Conversation, Peer.PeerId);

            foreach (uint Group in Caller.Groups)
                ReleaseGroup(Caller.ProcessId, Group);

            List<RegistrarConnection> Connections = Caller.Connections;
            int Kept = 0;
            for (int Index = 0; Index < Connections.Count; Index++)
            {
                if (Connections[Index].Accepted)
                    Connections[Kept++] = Connections[Index];
                else
                    ReleaseReservations(Connections[Index]);
            }

            Connections.RemoveRange(Kept, Connections.Count - Kept);
        }

        // A host client lives as long as the emulator.
        internal Client RegisterHostClient(uint ProcessId, uint ThreadId)
        {
            Client Host = new Client { ClientId = ++NextClientId, ProcessId = ProcessId, ThreadId = ThreadId };
            if (TryReserveGroup(ProcessId, out uint Group))
                Host.Groups.Add(Group);

            Clients.Add(Host.ClientId, Host);
            return Host;
        }

        // NT: RemoteRegistrarServer::RegisterPort. The ports belong to the thread that registers them.
        internal bool TryRegisterPort(Client Owner, Guid Port, string Name)
        {
            if (!HasRegistrationRoom("a port") || !Owner.Ports.TryAdd(Port, Name))
                return false;

            Registrations++;
            return true;
        }

        private bool HasRegistrationRoom(string What)
        {
            if (Registrations < MemoryBudget.CoreMessagingRegistrations)
                return true;

            Utils.LogError($"[-] CoreMessaging registrar: refused {What} past the limit of {MemoryBudget.CoreMessagingRegistrations} registrations.");
            return false;
        }

        // False when the scope is full, and true with the result of the registration otherwise.
        internal bool TryRegisterObject(Client Owner, string Name, uint Scope, ulong Identity, Guid Port, uint Type, out uint Result)
        {
            Result = MessagingDuplicateName;
            bool Session = Scope == SessionScope;
            if (Session ? !HasRegistrationRoom("an object") : ProcessObjects.Count >= MaxProcessRegistrations)
                return false;

            ObjectKey Key = new ObjectKey(Scope, Type, Name);
            if (!(Session ? SessionObjects : ProcessObjects).TryAdd(Key, new RegisteredObject(Owner, Identity, Port)))
                return true;

            Owner.Objects.Add(Key);
            if (Session)
                Registrations++;
            Result = MessagingSuccess;
            return true;
        }

        internal RegistrarConnection TryCompleteConnection(Client Server, ulong ClientId)
        {
            if (!Clients.TryGetValue(ClientId, out Client ClientThread))
                return null;

            foreach (RegistrarConnection Record in ClientThread.Connections)
            {
                if (Record.Accepted || Record.Server != Server)
                    continue;

                Record.Accepted = true;
                return Record;
            }

            return null;
        }

        internal void ReleaseConnection(RegistrarConnection Record)
        {
            if (Record.ClientThread.Connections.Remove(Record))
                ReleaseReservations(Record);
        }

        private void ReleaseReservations(RegistrarConnection Record)
        {
            ReleaseGroup(Record.ClientThread.ProcessId, Record.ClientGroup);
            ReleaseGroup(Record.Server.ProcessId, Record.ServerGroup);
            Registrations--;
        }

        private bool TryReserveGroup(uint ProcessId, out uint Group)
        {
            ref LowestFreeIds Pool = ref CollectionsMarshal.GetValueRefOrAddDefault(GroupPools, ProcessId, out _);
            Pool ??= new LowestFreeIds(1, MaxGroups);
            return Pool.TryTake(out Group);
        }

        private void ReleaseGroup(uint ProcessId, uint Group) => GroupPools.GetValueOrDefault(ProcessId)?.Release(Group);

        private void ForgetObject(ObjectKey Key)
        {
            if (Key.Scope != SessionScope)
            {
                ProcessObjects.Remove(Key);
                return;
            }

            if (SessionObjects.Remove(Key))
                Registrations--;
        }

        // NT: RemoteRegistrarServer::RegisterThread reserves a group of the client process on every call.
        private NTSTATUS RegisterThread(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.AtEnd)
                return Malformed(RegisterThreadMethod);

            uint Result = MessagingNoMoreIds;
            if (TryReserveGroup(Caller.ProcessId, out uint Group))
            {
                Caller.Groups.Add(Group);
                Result = MessagingSuccess;
            }

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Result);
            Call.UInt64(Caller.ClientId);
            Call.Guid(Guid.Empty);
            Call.UInt32(Group);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyRegisterThreadMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT gives a repeated call for the same server and port the same groups until the server accepts.
        private NTSTATUS PrepareConnection(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadFixed(PendingConnectionSize, out ReadOnlySpan<byte> Request) || !Parameters.AtEnd)
                return Malformed(PrepareConnectionMethod);

            if (BinaryPrimitives.ReadUInt64LittleEndian(Request.Slice(OffPendingIdentity0)) != 0)
                return ProtocolError(PrepareConnectionMethod);

            Clients.TryGetValue(BinaryPrimitives.ReadUInt64LittleEndian(Request.Slice(OffPendingServerClient)), out Client Server);
            if (Server != null && Server.ProcessId == Caller.ProcessId)
            {
                Utils.LogError("[-] CoreMessaging registrar: PrepareConnection to a thread of the calling process is not served.");
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            Guid Port = new Guid(Request.Slice(OffPendingPort, 16));
            bool ServerKnown = Server != null && Server.Group != 0;
            if (ServerKnown && Port == Guid.Empty)
                return ProtocolError(PrepareConnectionMethod);

            uint Result = MessagingClientNotFound;
            RegistrarConnection Record = null;
            string PortName = null;
            if (ServerKnown && Server.Ports.TryGetValue(Port, out PortName))
                Result = Prepare(Caller, Server, Port, out Record);

            Span<byte> Pending = stackalloc byte[PendingConnectionSize];
            Pending.Clear();
            if (Result == MessagingSuccess)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Pending.Slice(OffPendingIdentity0), HIdentityAllocator.SessionIdentity(Server.Group, 0));
                BinaryPrimitives.WriteUInt32LittleEndian(Pending.Slice(OffPendingClientGroup), Record.ClientGroup);
                BinaryPrimitives.WriteUInt32LittleEndian(Pending.Slice(OffPendingServerGroup), Record.ServerGroup);
                BinaryPrimitives.WriteUInt64LittleEndian(Pending.Slice(OffPendingIdentity1), HIdentityAllocator.SessionIdentity(Server.Group, 1));
            }

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Result);
            Call.String(Result == MessagingSuccess ? PortName : null);
            // The VM id of the server process and the port id across partitions, both empty on one partition.
            Call.Guid(Guid.Empty);
            Call.Guid(Guid.Empty);
            Call.Bytes(Pending);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyPrepareConnectionMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private uint Prepare(Client Caller, Client Server, Guid Port, out RegistrarConnection Record)
        {
            foreach (RegistrarConnection Pending in Caller.Connections)
            {
                if (!Pending.Accepted && Pending.Server == Server && Pending.Port == Port)
                {
                    Record = Pending;
                    return MessagingSuccess;
                }
            }

            Record = null;
            if (!HasRegistrationRoom("a connection") || !TryReserveGroup(Server.ProcessId, out uint ServerGroup))
                return MessagingNoMoreIds;

            if (!TryReserveGroup(Caller.ProcessId, out uint ClientGroup))
            {
                ReleaseGroup(Server.ProcessId, ServerGroup);
                return MessagingNoMoreIds;
            }

            Record = new RegistrarConnection { ClientThread = Caller, Server = Server, Port = Port, ClientGroup = ClientGroup, ServerGroup = ServerGroup };
            Caller.Connections.Add(Record);
            Registrations++;
            return MessagingSuccess;
        }

        private NTSTATUS CloseConnection(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadFixed(PendingConnectionSize, out ReadOnlySpan<byte> Pending) || !Parameters.AtEnd)
                return Malformed(CloseConnectionMethod);

            ulong ServerClientId = BinaryPrimitives.ReadUInt64LittleEndian(Pending.Slice(OffPendingServerClient));
            Guid Port = new Guid(Pending.Slice(OffPendingPort, 16));
            uint ClientGroup = BinaryPrimitives.ReadUInt32LittleEndian(Pending.Slice(OffPendingClientGroup));
            foreach (RegistrarConnection Record in Caller.Connections)
            {
                if (Record.Server.ClientId != ServerClientId || Record.Port != Port || Record.ClientGroup != ClientGroup)
                    continue;

                if (!Record.Accepted)
                    ReleaseConnection(Record);
                break;
            }

            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyCloseConnectionMethod, Sequence, null);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The VM id of the named client is empty on one partition.
        private NTSTATUS GetExtendedInformation(ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> Routing) || !Parameters.AtEnd)
                return Malformed(GetExtendedInformationMethod);

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Clients.ContainsKey(CoreMessagingRouting.ClientId(Routing)) ? MessagingSuccess : MessagingClientNotFound);
            Call.Guid(Guid.Empty);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyGetExtendedInformationMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryCheckScope(BinaryEmulator Instance, ReadOnlySpan<byte> Scope, ushort Method, out NTSTATUS Failure)
        {
            Failure = NTSTATUS.STATUS_SUCCESS;
            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            if (ScopeKind != ProcessScope && ScopeKind != SessionScope)
            {
                Failure = ScopeNotServed(Method, ScopeKind);
                return false;
            }

            if (ScopeKind == ProcessScope ? !IsOwnProcessScope(Instance, Scope) : !IsCallerSessionScope(Scope))
            {
                Failure = ProtocolError(Method);
                return false;
            }

            return true;
        }

        private NTSTATUS RegisterObject(BinaryEmulator Instance, Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadUInt64(out ulong Identity) || !Parameters.TryReadGuid(out Guid Port)
                || !Parameters.TryReadUInt32(out uint Type) || !Parameters.AtEnd)
                return Malformed(RegisterObjectMethod);

            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            if ((ScopeKind != 0 && Port == Guid.Empty) || Type >= ObjectTypeCount || !IsValidName(Name))
                return ProtocolError(RegisterObjectMethod);

            if (!TryCheckScope(Instance, Scope, RegisterObjectMethod, out NTSTATUS Failure))
                return Failure;

            if (Name.StartsWith(ReservedKernelPrefix, StringComparison.Ordinal))
                return ProtocolError(RegisterObjectMethod);

            if (!TryRegisterObject(Caller, Name.ToString(), ScopeKind, Identity, Port, Type, out uint Result))
                return ScopeKind == ProcessScope ? ProtocolError(RegisterObjectMethod) : NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Result);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyRegisterObjectMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT sets the bool only for a type 1 object of a container thread, and there are none here.
        private NTSTATUS FindObject(BinaryEmulator Instance, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadUInt32(out uint Type) || !Parameters.AtEnd)
                return Malformed(FindObjectMethod);

            if (Type >= ObjectTypeCount || !IsValidName(Name))
                return ProtocolError(FindObjectMethod);

            if (!TryCheckScope(Instance, Scope, FindObjectMethod, out NTSTATUS Failure))
                return Failure;

            uint ScopeKind = BinaryPrimitives.ReadUInt32LittleEndian(Scope);
            Dictionary<ObjectKey, RegisteredObject> Table = ScopeKind == SessionScope ? SessionObjects : ProcessObjects;
            Span<byte> Routing = stackalloc byte[CoreMessagingRouting.Size];
            Routing.Clear();
            uint Result = MessagingObjectNotFound;
            if (Table.TryGetValue(new ObjectKey(ScopeKind, Type, Name.ToString()), out RegisteredObject Found))
            {
                Found.Owner.WriteRoutingInfo(Routing, Found.Identity, Found.Port);
                Result = MessagingSuccess;
            }

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Result);
            Call.Bool(false);
            Call.Bytes(Routing);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyFindObjectMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: RegistrationNameMaps::CleanupRegistrationCommon finds the name only among those of the calling thread.
        private NTSTATUS UnregisterObject(BinaryEmulator Instance, Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadString(out ReadOnlySpan<char> Name) || !Parameters.TryReadFixed(ScopeIdSize, out ReadOnlySpan<byte> Scope)
                || !Parameters.TryReadUInt32(out uint Type) || !Parameters.AtEnd)
                return Malformed(UnregisterObjectMethod);

            if (Type >= ObjectTypeCount || !IsValidName(Name))
                return ProtocolError(UnregisterObjectMethod);

            if (!TryCheckScope(Instance, Scope, UnregisterObjectMethod, out NTSTATUS Failure))
                return Failure;

            ObjectKey Key = new ObjectKey(BinaryPrimitives.ReadUInt32LittleEndian(Scope), Type, Name.ToString());
            uint Result = MessagingObjectNotFound;
            if (Caller.Objects.Remove(Key))
            {
                ForgetObject(Key);
                Result = MessagingSuccess;
            }

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Result);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyUnregisterObjectMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsValidName(ReadOnlySpan<char> Name) => !Name.IsEmpty && Name.Length <= MaxNameLength;

        // The registrar answers one call at a time, so its replies share one writer.
        private CoreMessagingWriter BeginReply()
        {
            ReplyWriter.Clear();
            return ReplyWriter;
        }

        // NT: RegisteredObjectValidator::ValidateRegistrarScope. A process scope names the caller's process or 0.
        private static bool IsOwnProcessScope(BinaryEmulator Instance, ReadOnlySpan<byte> Scope)
        {
            uint ProcessId = BinaryPrimitives.ReadUInt32LittleEndian(Scope.Slice(4));
            return ProcessId == 0 || ProcessId == Instance.WinHelper.PID;
        }

        private NTSTATUS RegisterPort(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadGuid(out Guid PortId) || !Parameters.TryReadString(out ReadOnlySpan<char> Name)
                || !Parameters.TryReadGuid(out _) || !Parameters.AtEnd)
                return Malformed(RegisterPortMethod);

            if (!IsValidName(Name) || Caller.Ports.ContainsKey(PortId))
                return ProtocolError(RegisterPortMethod);

            if (!TryRegisterPort(Caller, PortId, Name.ToString()))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyRegisterPortMethod, Sequence, null);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS UnregisterPort(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadGuid(out Guid PortId) || !Parameters.AtEnd)
                return Malformed(UnregisterPortMethod);

            if (!Caller.Ports.Remove(PortId))
                return ProtocolError(UnregisterPortMethod);

            Registrations--;
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyUnregisterPortMethod, Sequence, null);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS GetOrCreateReverseConnectionPortId(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadGuid(out Guid Key) || !Parameters.AtEnd)
                return Malformed(GetOrCreateReverseConnectionPortIdMethod);

            if (Key == Guid.Empty)
                return ProtocolError(GetOrCreateReverseConnectionPortIdMethod);

            if (!Caller.ReverseConnectionPortIds.TryGetValue(Key, out Guid Id))
            {
                if (!HasRegistrationRoom("a reverse connection port"))
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                Id = Guid.NewGuid();
                Caller.ReverseConnectionPortIds.Add(Key, Id);
                Caller.ReverseConnectionPortKeys.Add(Id, Key);
                Registrations++;
            }

            CoreMessagingWriter Call = BeginReply();
            Call.Guid(Id);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyGetOrCreateReverseConnectionPortIdMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS UnregisterReverseConnectionPort(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
        {
            Reply = null;
            if (!Parameters.TryReadGuid(out Guid Id) || !Parameters.AtEnd)
                return Malformed(UnregisterReverseConnectionPortMethod);

            if (!Caller.ReverseConnectionPortKeys.Remove(Id, out Guid Key))
                return ProtocolError(UnregisterReverseConnectionPortMethod);

            Caller.ReverseConnectionPortIds.Remove(Key);
            Registrations--;
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyUnregisterReverseConnectionPortMethod, Sequence, null);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: ServerConversationOperations::RegisterConversationClient. With no conversation of that name, an eager
        // client creates one, and a server that registers later is announced to it.
        private NTSTATUS RegisterConversationClient(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
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

                if (!HasRegistrationRoom("a conversation"))
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

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
            Conversation.Clients.Add(PeerId, Caller);
            Caller.ConversationPeers.Add(new ConversationPeer(Conversation, PeerId));
            ConversationClients++;
            return ConversationClientReply(MessagingSuccess, PeerId, ++LastConversationUniqueId, Conversation, Sequence, out Reply);
        }

        private NTSTATUS ConversationClientReply(uint Result, uint PeerId, ulong UniqueId, Conversation Conversation, uint Sequence, out byte[] Reply)
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

            CoreMessagingWriter Call = BeginReply();
            Call.UInt32(Result);
            Call.UInt32(PeerId);
            Call.UInt64(UniqueId);
            Call.Bytes(Info);
            // The server peers of the conversation, which no server joins here.
            Call.Bytes(ReadOnlySpan<byte>.Empty);
            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyRegisterConversationClientMethod, Sequence, Call);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: ServerConversationOperations::ReleaseConversationClient. A name with no conversation still gets the reply.
        private NTSTATUS ReleaseConversationClient(Client Caller, ref CoreMessagingReader Parameters, uint Sequence, out byte[] Reply)
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
                if (!Conversation.Clients.TryGetValue(PeerId, out Client Owner) || Owner != Caller)
                    return ProtocolError(ReleaseConversationClientMethod);

                Caller.ConversationPeers.Remove(new ConversationPeer(Conversation, PeerId));
                ForgetConversationClient(Conversation, PeerId);
            }

            Reply = CoreMessagingCall.ToReply(ClientInterface, ReplyReleaseConversationClientMethod, Sequence, null);
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
    }
}
