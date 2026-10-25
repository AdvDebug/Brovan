using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.RPC
{
    internal abstract class HostMessagingEndpoint
    {
        internal ulong Identity { get; set; }

        internal HostMessagingConnection Connection { get; set; }

        internal int Holds { get; private set; }

        internal void AddHold() => Holds++;

        internal int DropHold() => --Holds;

        internal abstract void Receive(HostMessagingCall Call, ReadOnlySpan<byte> Payload);

        internal virtual void Released()
        {
        }
    }

    internal sealed class HostMessagingCall
    {
        internal readonly BinaryEmulator Instance;
        internal readonly HostMessagingConnection Connection;
        private readonly CoreMessagingBatchWriter Answers = new CoreMessagingBatchWriter();

        internal HostMessagingCall(BinaryEmulator Instance, HostMessagingConnection Connection)
        {
            this.Instance = Instance;
            this.Connection = Connection;
        }

        internal HostMessagingServer Server => Connection.Server;

        internal void Send(ulong Target, ReadOnlySpan<byte> Header, ReadOnlySpan<byte> Body)
        {
            int Size = CoreMessagingBatchReader.MessageHeaderSize + Header.Length + Body.Length;
            if (Answers.Length + Size + CoreMessagingBatchReader.Alignment > HostMessagingConnection.MaxBatchBytes)
                Flush();

            Answers.Add(Target, Header, Body);
        }

        internal void SetPendingResult(ReadOnlySpan<byte> Result) => Connection.SetPendingResult(Result);

        // NT has the client's thread endpoint reserve the new identity first (MessageSession::AllocateRemoteEndpoint).
        internal bool TryAllocateRemoteEndpoint(HostMessagingEndpoint Endpoint, ReadOnlySpan<byte> ClientRouting, Span<byte> ProxyRouting, out ulong Proxy)
        {
            if (!Connection.ClientIdentities.TryAllocate(out Proxy))
                return false;

            ClientRouting.CopyTo(ProxyRouting);
            CoreMessagingRouting.SetIdentity(ProxyRouting, Proxy);
            if (!Connection.TryAddStub(Endpoint, Proxy, ProxyRouting))
            {
                Connection.ClientIdentities.Free(Proxy);
                return false;
            }

            CoreMessagingWriter Parameters = new CoreMessagingWriter();
            Parameters.UInt64(Proxy);
            Span<byte> Header = stackalloc byte[CoreMessagingCall.HeaderSize];
            CoreMessagingCall.WriteHeader(Header, HostMessagingServer.ThreadEndpointInterface, HostMessagingServer.ReserveHIdentityMethod, Parameters.Written.Length);
            Send(HIdentityAllocator.SessionIdentity(Connection.Client.Group, 0), Header, Parameters.Written);
            return true;
        }

        internal void Flush()
        {
            if (Answers.IsEmpty)
                return;

            Connection.Post(Instance, Answers);
            Answers.Clear();
        }
    }

    internal sealed class HostMessagingConnection
    {
        internal const int MaxBatchBytes = 0x1000;

        internal sealed class Stub
        {
            internal readonly ulong Proxy;
            internal readonly byte[] Routing;
            internal int Pushes;

            internal Stub(ulong Proxy, ReadOnlySpan<byte> Routing)
            {
                this.Proxy = Proxy;
                this.Routing = Routing.ToArray();
            }
        }

        internal readonly HostMessagingServer Server;
        internal readonly AlpcConnection Alpc;
        internal readonly CoreMessagingRegistrarPort.RegistrarConnection Record;
        internal readonly HIdentityAllocator ClientIdentities;
        private readonly Dictionary<HostMessagingEndpoint, List<Stub>> Stubs = new Dictionary<HostMessagingEndpoint, List<Stub>>();
        private readonly HashSet<HostMessagingEndpoint> Owned = new HashSet<HostMessagingEndpoint>();
        private readonly HashSet<ulong> Reserved = new HashSet<ulong>();
        private readonly HashSet<ulong> AwaitingFree = new HashSet<ulong>();
        private byte[] PendingResult;
        private uint NextSequence;
        private List<byte[]> SplitBatch;
        private int SplitBatchBytes;
        private ushort SplitBatchCount;
        private uint SplitBatchSequence;

        internal HostMessagingConnection(HostMessagingServer Server, AlpcConnection Alpc, CoreMessagingRegistrarPort.RegistrarConnection Record)
        {
            this.Server = Server;
            this.Alpc = Alpc;
            this.Record = Record;
            ClientIdentities = new HIdentityAllocator(Record.ClientGroup, ThreadGroup: false);
        }

        internal bool Closed { get; private set; }

        internal CoreMessagingRegistrarPort.Client Client => Record.ClientThread;

        // A run-time endpoint of this connection lives while it has a stub or a hold.
        internal bool TryAddStub(HostMessagingEndpoint Endpoint, ulong Proxy, ReadOnlySpan<byte> Routing)
        {
            if (FindStub(Endpoint, Proxy) != null || !Server.TryReserveObject())
                return false;

            ref List<Stub> List = ref CollectionsMarshal.GetValueRefOrAddDefault(Stubs, Endpoint, out _);
            List ??= new List<Stub>(1);
            List.Add(new Stub(Proxy, Routing));
            return true;
        }

        internal bool TryCountPush(HostMessagingEndpoint Endpoint, out ulong Proxy)
        {
            Proxy = 0;
            if (!Stubs.TryGetValue(Endpoint, out List<Stub> List))
                return false;

            List[0].Pushes++;
            Proxy = List[0].Proxy;
            return true;
        }

        internal bool HasStubs(HostMessagingEndpoint Endpoint) => Stubs.ContainsKey(Endpoint);

        // The span keeps the stubs it started with when a message to one of them adds stubs.
        internal ReadOnlySpan<Stub> StubsOf(HostMessagingEndpoint Endpoint)
            => Stubs.TryGetValue(Endpoint, out List<Stub> List) ? CollectionsMarshal.AsSpan(List) : ReadOnlySpan<Stub>.Empty;

        internal void CountPush(HostMessagingEndpoint Endpoint, ulong Proxy)
        {
            Stub Found = FindStub(Endpoint, Proxy);
            if (Found != null)
                Found.Pushes++;
        }

        internal void Materialized(HostMessagingEndpoint Endpoint, ulong Proxy)
        {
            Stub Found = FindStub(Endpoint, Proxy);
            if (Found != null && Found.Pushes > 0)
                Found.Pushes--;
        }

        // NT keeps a stub while a push of it is not answered.
        internal bool TryRemoveStub(HostMessagingEndpoint Endpoint, ulong Proxy)
        {
            if (!Stubs.TryGetValue(Endpoint, out List<Stub> List))
                return false;

            int Index = List.Count - 1;
            while (Index >= 0 && List[Index].Proxy != Proxy)
                Index--;

            if (Index < 0 || List[Index].Pushes > 0)
                return false;

            List.RemoveAt(Index);
            StubGone(Proxy);
            if (List.Count != 0)
                return true;

            Stubs.Remove(Endpoint);
            if (Owned.Contains(Endpoint) && Endpoint.Holds == 0)
                Server.Remove(Endpoint);
            return true;
        }

        internal void DropStubs(HostMessagingEndpoint Endpoint)
        {
            if (!Stubs.Remove(Endpoint, out List<Stub> List))
                return;

            foreach (Stub Entry in List)
                StubGone(Entry.Proxy);
        }

        // NT: the identity of a proxy the server pushed stays taken until the client frees it (NotifyHIDENTITYFreed).
        private void StubGone(ulong Proxy)
        {
            if (!ClientIdentities.IsLive(Proxy) || !AwaitingFree.Add(Proxy))
                Server.ReleaseObject();
        }

        internal void FreeClientIdentity(ulong Identity)
        {
            ClientIdentities.Free(Identity);
            if (AwaitingFree.Remove(Identity))
                Server.ReleaseObject();
        }

        private Stub FindStub(HostMessagingEndpoint Endpoint, ulong Proxy)
        {
            if (!Stubs.TryGetValue(Endpoint, out List<Stub> List))
                return null;

            foreach (Stub Entry in List)
            {
                if (Entry.Proxy == Proxy)
                    return Entry;
            }

            return null;
        }

        internal void Own(HostMessagingEndpoint Endpoint) => Owned.Add(Endpoint);

        internal void Disown(HostMessagingEndpoint Endpoint) => Owned.Remove(Endpoint);

        internal bool TryGetEndpoint(ulong Identity, out HostMessagingEndpoint Endpoint)
            => Server.TryFind(Identity, out Endpoint) && Endpoint.Connection == this;

        // A reservation counts as an object until an endpoint takes the identity.
        internal bool TryReserve(ulong Identity)
        {
            if (HIdentityAllocator.GroupOf(Identity) != Record.ServerGroup || Reserved.Contains(Identity) || Server.TryFind(Identity, out _)
                || !Server.TryReserveObject())
                return false;

            Reserved.Add(Identity);
            return true;
        }

        internal bool TryTakeReservation(ulong Identity) => Reserved.Remove(Identity);

        internal bool TryFreeReserved(ulong Identity)
        {
            if (HIdentityAllocator.GroupOf(Identity) != Record.ServerGroup)
                return false;

            if (Reserved.Remove(Identity))
                Server.ReleaseObject();
            else if (TryGetEndpoint(Identity, out HostMessagingEndpoint Endpoint))
                Server.Remove(Endpoint);

            return true;
        }

        internal void SetPendingResult(ReadOnlySpan<byte> Result) => PendingResult = Result.ToArray();

        // The checks follow AlpcConnection::ValidateSubsequentBufferInBatch. Complete stays null until the last buffer.
        internal bool TryJoinSplitBatch(in CoreMessagingBuffer Header, ReadOnlySpan<byte> Payload, out List<byte[]> Complete)
        {
            Complete = null;
            if (Header.BatchIndex == 0)
            {
                DropSplitBatch();
                SplitBatch = new List<byte[]>();
                SplitBatchCount = Header.BatchCount;
                SplitBatchSequence = Header.Sequence;
            }
            else if (SplitBatch == null || Header.BatchIndex != SplitBatch.Count || Header.BatchCount != SplitBatchCount
                || Header.Sequence != SplitBatchSequence)
            {
                DropSplitBatch();
                return false;
            }

            int Held = HostMessagingServer.HeldEntryBytes + Payload.Length;
            if (!Server.TryHoldBytes(Held))
            {
                DropSplitBatch();
                return false;
            }

            SplitBatch.Add(Payload.ToArray());
            SplitBatchBytes += Held;
            if (Header.BatchIndex == Header.BatchCount - 1)
            {
                Complete = SplitBatch;
                DropSplitBatch();
            }

            return true;
        }

        private void DropSplitBatch()
        {
            Server.ReleaseBytes(SplitBatchBytes);
            SplitBatchBytes = 0;
            SplitBatch = null;
        }

        // NT sets the result flag of a ping that wants no result.
        internal byte[] AnswerPing(in CoreMessagingBuffer Ping)
        {
            if (!Ping.WantsResult)
                return CoreMessagingBuffer.PingReply(Ping.Sequence, true, ReadOnlySpan<byte>.Empty);

            byte[] Result = PendingResult;
            PendingResult = null;
            return CoreMessagingBuffer.PingReply(Ping.Sequence, Result != null, Result);
        }

        internal void Post(BinaryEmulator Instance, CoreMessagingBatchWriter Batch)
        {
            if (!Closed)
                Server.Send(Instance, Alpc, Batch.ToBuffer(NextSequence++));
        }

        // An endpoint that Remove releases can remove others of this connection, and Closed keeps new ones out.
        internal void Close()
        {
            Closed = true;
            foreach (HostMessagingEndpoint Endpoint in Owned)
                Server.Remove(Endpoint);

            int Objects = AwaitingFree.Count + Reserved.Count;
            foreach (List<Stub> List in Stubs.Values)
                Objects += List.Count;

            Server.ReleaseObjects(Objects);
            Stubs.Clear();
            AwaitingFree.Clear();
            Reserved.Clear();
            DropSplitBatch();
        }
    }

    // A CoreMessaging server the host runs for a process the guest does not run. It answers in its clients' syscalls.
    internal sealed class HostMessagingServer : AlpcHostServer
    {
        private const int ConnectDataSize = 0x18;

        internal const ushort ThreadEndpointInterface = 2;
        internal const ushort ReserveHIdentityMethod = 0;
        private const ushort FreeHIdentityMethod = 1;
        private const ushort NotifyHIdentityFreedMethod = 3;

        private sealed class ThreadEndpoint : HostMessagingEndpoint
        {
            internal override void Receive(HostMessagingCall Call, ReadOnlySpan<byte> Payload)
            {
                if (!CoreMessagingCall.TryRead(Payload, out ushort Interface, out ushort Method, out CoreMessagingReader Parameters)
                    || Interface != ThreadEndpointInterface)
                {
                    Utils.LogError("[-] CoreMessaging: a client sent a thread endpoint call that Brovan's server does not serve.");
                    return;
                }

                HostMessagingConnection Connection = Call.Connection;
                switch (Method)
                {
                    case ReserveHIdentityMethod when Parameters.TryReadUInt64(out ulong Identity) && Parameters.AtEnd:
                        if (!Connection.TryReserve(Identity))
                            Utils.LogError($"[-] CoreMessaging: Brovan's server refused to reserve identity 0x{Identity:X16} outside its connection's group, twice or past the limit of objects.");
                        break;
                    case FreeHIdentityMethod when Parameters.TryReadUInt64(out ulong Identity) && Parameters.AtEnd:
                        if (!Connection.TryFreeReserved(Identity))
                            Utils.LogError($"[-] CoreMessaging: Brovan's server refused to free identity 0x{Identity:X16} outside its connection's group.");
                        break;
                    case NotifyHIdentityFreedMethod when Parameters.TryReadFixed(CoreMessagingRouting.Size, out ReadOnlySpan<byte> Routing) && Parameters.AtEnd:
                        if (!Connection.Client.IsNamedBy(Routing) || !Connection.ClientIdentities.Owns(CoreMessagingRouting.Identity(Routing)))
                        {
                            Utils.LogError("[-] CoreMessaging: Brovan's server refused a freed identity of another thread or group.");
                            break;
                        }

                        Connection.FreeClientIdentity(CoreMessagingRouting.Identity(Routing));
                        break;
                    default:
                        Utils.LogError($"[-] CoreMessaging: a client sent thread endpoint method {Method}, which Brovan's server does not serve.");
                        break;
                }
            }
        }

        private readonly CoreMessagingRegistrarPort Registrar;
        private readonly HIdentityAllocator Identities;
        private readonly Dictionary<ulong, HostMessagingEndpoint> Endpoints = new Dictionary<ulong, HostMessagingEndpoint>();
        private int Objects;
        private int HeldBytes;
        private ulong ClientHandles;

        internal readonly CoreMessagingRegistrarPort.Client Client;
        internal readonly Guid Port;

        private HostMessagingServer(CoreMessagingRegistrarPort Registrar, CoreMessagingRegistrarPort.Client Client, Guid Port)
        {
            this.Registrar = Registrar;
            this.Client = Client;
            this.Port = Port;
            Identities = new HIdentityAllocator(Client.Group, ThreadGroup: true);
        }

        internal static HostMessagingServer Create(WinSysHelper Helper, CoreMessagingRegistrarPort Registrar, uint ProcessId, uint ThreadId, HostMessagingEndpoint Session)
        {
            CoreMessagingRegistrarPort.Client Client = Registrar.RegisterHostClient(ProcessId, ThreadId);
            Guid Port = Guid.NewGuid();
            string Name = $"\\BaseNamedObjects\\[CoreUI]-PID({ProcessId})-TID({ThreadId}) {Port}";
            if (Client.Group == 0 || !Registrar.TryRegisterPort(Client, Port, Name))
            {
                Utils.LogError($"[-] CoreMessaging: Brovan's server of process {ProcessId} could not register its port.");
                return null;
            }

            HostMessagingServer Server = new HostMessagingServer(Registrar, Client, Port) { ProcessId = ProcessId, ThreadId = ThreadId };
            ThreadEndpoint Thread = new ThreadEndpoint { Identity = HIdentityAllocator.SessionIdentity(Client.Group, 0) };
            Server.Endpoints.Add(Thread.Identity, Thread);
            Session.Identity = HIdentityAllocator.SessionIdentity(Client.Group, 1);
            Server.Endpoints.Add(Session.Identity, Session);
            Helper.WinPorts.Add(AlpcMessaging.CreateHostPort(Name, Server));
            return Server;
        }

        internal void WriteRoutingInfo(Span<byte> Routing, ulong Identity) => Client.WriteRoutingInfo(Routing, Identity, Port);

        internal bool TryReserveObject()
        {
            if (Objects >= MemoryBudget.HostMessagingObjects)
                return false;

            Objects++;
            return true;
        }

        internal void ReleaseObject() => Objects--;

        internal void ReleaseObjects(int Count) => Objects -= Count;

        internal bool TryAddNamed(string Name, HostMessagingEndpoint Endpoint)
        {
            if (!Identities.TryAllocate(out ulong Identity))
                return false;

            if (!Registrar.TryRegisterObject(Client, Name, CoreMessagingRegistrarPort.SessionScope, Identity, Port, 0, out uint Result)
                || Result != CoreMessagingRegistrarPort.MessagingSuccess)
            {
                Utils.LogError($"[-] CoreMessaging: Brovan's server could not register \"{Name}\".");
                Identities.Free(Identity);
                return false;
            }

            Endpoint.Identity = Identity;
            Endpoints.Add(Identity, Endpoint);
            return true;
        }

        internal bool TryAdd(HostMessagingConnection Connection, HostMessagingEndpoint Endpoint)
        {
            if (Connection.Closed || !TryReserveObject())
                return false;

            if (!Identities.TryAllocate(out ulong Identity))
            {
                ReleaseObject();
                return false;
            }

            Attach(Connection, Identity, Endpoint);
            return true;
        }

        internal bool TryAdd(HostMessagingConnection Connection, ulong Identity, HostMessagingEndpoint Endpoint)
        {
            if (Connection.Closed || !Connection.TryTakeReservation(Identity))
                return false;

            Attach(Connection, Identity, Endpoint);
            return true;
        }

        internal bool TryFind(ulong Identity, out HostMessagingEndpoint Endpoint) => Endpoints.TryGetValue(Identity, out Endpoint);

        // NT keeps an object that another object names, but Remove and the end of the connection ignore holds.
        internal void Hold(HostMessagingEndpoint Endpoint) => Endpoint.AddHold();

        internal void Unhold(HostMessagingEndpoint Endpoint)
        {
            if (Endpoint.DropHold() == 0 && Endpoint.Connection != null && !Endpoint.Connection.HasStubs(Endpoint))
                Remove(Endpoint);
        }

        // Each held buffer or value also costs this much, so that empty ones count too.
        internal const int HeldEntryBytes = 0x20;

        internal bool TryHoldBytes(int Bytes)
        {
            if (Bytes > MemoryBudget.PooledIoBytes - HeldBytes)
                return false;

            HeldBytes += Bytes;
            return true;
        }

        internal void ReleaseBytes(int Bytes) => HeldBytes -= Bytes;

        private void Attach(HostMessagingConnection Connection, ulong Identity, HostMessagingEndpoint Endpoint)
        {
            Endpoint.Identity = Identity;
            Endpoint.Connection = Connection;
            Endpoints.Add(Identity, Endpoint);
            Connection.Own(Endpoint);
        }

        internal void Remove(HostMessagingEndpoint Endpoint)
        {
            if (Endpoint.Connection == null || !Endpoints.Remove(Endpoint.Identity))
                return;

            Endpoint.Connection.Disown(Endpoint);
            Endpoint.Connection.DropStubs(Endpoint);
            Identities.Free(Endpoint.Identity);
            ReleaseObject();
            Endpoint.Released();
        }

        internal override bool Connect(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, out byte[] Reply, out object State)
        {
            Reply = null;
            State = null;
            if (Data.Length != ConnectDataSize)
            {
                Utils.LogError($"[-] CoreMessaging: Brovan's server refused a connect message of {Data.Length} bytes.");
                return false;
            }

            CoreMessagingRegistrarPort.RegistrarConnection Record = Registrar.TryCompleteConnection(Client, BinaryPrimitives.ReadUInt64LittleEndian(Data));
            if (Record == null)
            {
                Utils.LogError("[-] CoreMessaging: Brovan's server refused a connect that the registrar did not prepare.");
                return false;
            }

            if (!TryReserveObject())
            {
                Utils.LogError($"[-] CoreMessaging: Brovan's server refused a connect past the limit of {MemoryBudget.HostMessagingObjects} objects.");
                Registrar.ReleaseConnection(Record);
                return false;
            }

            // NT puts the server's handle of the client state where the client id was, and the client does not read it.
            State = new HostMessagingConnection(this, Connection, Record);
            Reply = Data.ToArray();
            BinaryPrimitives.WriteUInt64LittleEndian(Reply, ++ClientHandles);
            return true;
        }

        internal override NTSTATUS Receive(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, bool WaitsForReply, out byte[] Reply)
        {
            Reply = null;
            HostMessagingConnection State = (HostMessagingConnection)Connection.HostServerState;
            if (!CoreMessagingBuffer.TryRead(Data, out CoreMessagingBuffer Header, out ReadOnlySpan<byte> Payload))
            {
                Utils.LogError($"[-] CoreMessaging: Brovan's server got a buffer of {Data.Length} bytes that it does not serve.");
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (Header.Kind == CoreMessagingBuffer.KindPing && WaitsForReply && Payload.IsEmpty)
            {
                Reply = State.AnswerPing(Header);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Header.Kind != CoreMessagingBuffer.KindOneWay || WaitsForReply)
            {
                Utils.LogError($"[-] CoreMessaging: Brovan's server does not serve a buffer of kind {Header.Kind}.");
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            List<byte[]> Buffers = null;
            if (Header.BatchCount != 1)
            {
                if (!State.TryJoinSplitBatch(Header, Payload, out Buffers))
                {
                    Utils.LogError($"[-] CoreMessaging: Brovan's server got buffer {Header.BatchIndex} of {Header.BatchCount} out of its batch.");
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if (Buffers == null)
                    return NTSTATUS.STATUS_SUCCESS;
            }

            HostMessagingCall Call = new HostMessagingCall(Instance, State);
            if (Buffers == null)
                DeliverAll(Call, Payload);
            else
            {
                foreach (byte[] Buffer in Buffers)
                    DeliverAll(Call, Buffer);
            }

            Call.Flush();
            return NTSTATUS.STATUS_SUCCESS;
        }

        private void DeliverAll(HostMessagingCall Call, ReadOnlySpan<byte> Payload)
        {
            CoreMessagingBatchReader Batch = new CoreMessagingBatchReader(Payload);
            while (Batch.TryReadNext(out ulong Target, out ReadOnlySpan<byte> Message))
                Deliver(Call, Target, Message);
        }

        internal override void Disconnected(BinaryEmulator Instance, AlpcConnection Connection)
        {
            if (Connection.HostServerState is not HostMessagingConnection State)
                return;

            State.Close();
            Registrar.ReleaseConnection(State.Record);
            ReleaseObject();
        }

        private void Deliver(HostMessagingCall Call, ulong Target, ReadOnlySpan<byte> Message)
        {
            if (!Endpoints.TryGetValue(Target, out HostMessagingEndpoint Endpoint))
            {
                if ((Call.Instance.Settings.Flags & LogFlags.General) != 0)
                    Call.Instance.TriggerEventMessage($"[!] CoreMessaging: Brovan's server dropped a message to identity 0x{Target:X16}, which it does not serve.", LogFlags.General);
                return;
            }

            if (Endpoint.Connection != null && Endpoint.Connection != Call.Connection)
            {
                Utils.LogError($"[-] CoreMessaging: a client sent a message to identity 0x{Target:X16}, which belongs to another connection.");
                return;
            }

            Endpoint.Receive(Call, Message);
        }
    }
}
