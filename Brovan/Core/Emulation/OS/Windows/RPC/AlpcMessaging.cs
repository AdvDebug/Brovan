using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.Windows.RPC;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class AlpcReceiveQueue
    {
        internal readonly Queue<AlpcMessage> Pending = new Queue<AlpcMessage>();
        internal readonly List<AlpcWait> Receivers = new List<AlpcWait>();
        internal WinIoCompletion CompletionPort;
        internal ulong CompletionKey;
    }

    internal sealed class AlpcServerQueue : AlpcReceiveQueue
    {
        // Received, but not yet accepted or replied to.
        internal readonly Dictionary<uint, AlpcMessage> Delivered = new Dictionary<uint, AlpcMessage>();
        internal readonly HashSet<AlpcConnection> Connections = new HashSet<AlpcConnection>();
    }

    internal enum AlpcConnectionState : byte
    {
        Connecting,
        Connected,
        Closed,
    }

    internal sealed class AlpcConnection
    {
        internal WinPort ConnectionPort;
        // Null for a client that Brovan runs.
        internal WinPort ClientPort;
        internal AlpcConnectionState State;
        // NT: the server communication port can still reach the client after the connection port closes.
        internal bool ClientReachable;
        internal ulong PortContext;
        internal object HostServerState;
        internal ulong TokenId;
        internal uint ClosedCallbackId;
        internal uint NextSequence;
        internal uint NextClientSequence;
        internal AlpcWait ConnectWait;
        internal AlpcMessage PendingConnectReply;
        internal uint PendingReplyThread;
        internal AlpcHost Host;
        internal readonly List<AlpcMessage> AwaitingReply = new List<AlpcMessage>();
        internal int DeliveredDatagrams;

        internal AlpcSecurityContext Client;
        internal ulong ClientAuthenticationId;
        internal bool AllowImpersonation;
    }

    internal sealed class AlpcSecurityContext
    {
        internal WinToken Token { get; init; }
        internal SecurityQos Qos { get; init; }

        internal WinPort Owner;
        internal ServedClient? Served;
        internal ulong Handle;
        internal int Messages;
        internal bool Deleted;
    }

    internal sealed class ServedClient
    {
        internal int Handles = 1;
        internal readonly LrpcBindingTable Bindings = new LrpcBindingTable();
        // Answers to requests whose sender does not wait.
        internal AlpcReceiveQueue? Queue;
    }

    // What a reply takes over from its request. An LRPC bind's type flags 0x4000 give reply type 0x4002.
    internal readonly record struct AlpcRequestFacts(ushort TypeFlags, uint CallbackId, ulong MessageContext);

    // A client that Brovan runs. Its callbacks run under KernelLock in the guest server thread's syscall.
    internal sealed class AlpcHost
    {
        internal ulong ProcessId { get; init; }
        internal ulong ThreadId { get; init; }
        internal Action<NTSTATUS> Connected;
    }

    // The reply is in the shared scratch buffer, so it is valid only during the call.
    internal delegate void HostReplyHandler(NTSTATUS Status, ReadOnlySpan<byte> Reply);

    // A server that Brovan runs. It answers in the syscall of the guest client, under KernelLock.
    internal abstract class AlpcHostServer
    {
        internal ulong ProcessId { get; init; }
        internal ulong ThreadId { get; init; }

        // State goes to AlpcConnection.HostServerState when the server accepts.
        internal abstract bool Connect(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, out byte[] Reply, out object State);

        internal abstract NTSTATUS Receive(BinaryEmulator Instance, AlpcConnection Connection, ReadOnlySpan<byte> Data, bool WaitsForReply, out byte[] Reply);

        internal abstract void Disconnected(BinaryEmulator Instance, AlpcConnection Connection);

        // The message keeps Data without a copy, and the client cannot reply to it.
        internal bool Send(BinaryEmulator Instance, AlpcConnection Connection, byte[] Data) => AlpcMessaging.SendFromHostServer(Instance, this, Connection, Data);
    }

    internal sealed class AlpcMessage
    {
        internal ushort Type;
        internal ushort TypeFlags;
        internal byte[] Data;
        internal ulong ProcessId;
        internal ulong ThreadId;
        internal uint MessageId;
        internal uint CallbackId;
        internal uint Sequence;
        internal ulong MessageContext;
        internal AlpcConnection Connection;
        internal AlpcWait ReplyWait;
        internal HostReplyHandler HostReply;
        internal WinToken SenderToken;
        internal AlpcSecurityContext SecurityContext;

        internal bool WaitsForReply => ReplyWait != null || HostReply != null;
    }

    internal enum AlpcWaitKind : byte
    {
        Receive,
        Connect,
        Reply,
    }

    internal sealed class AlpcWait : ParkedIoRequest
    {
        internal AlpcWaitKind Kind;
        internal WinPort Port;
        internal ulong PortHandlePtr;
        internal ulong MessagePtr;
        internal ulong BufferLength;
        internal ulong BufferLengthPtr;
        internal ulong AttributesPtr;

        internal override WinFile File => null;

        internal override string WaitLabel => Kind switch
        {
            AlpcWaitKind.Receive => "alpc-receive",
            AlpcWaitKind.Connect => "alpc-connect",
            _ => "alpc-reply",
        };
    }

    // ALPC to guest ports of this process. Messages between the ports use x64 layouts.
    internal static class AlpcMessaging
    {
        // NT: PORT_MESSAGE on x64.
        internal const int HeaderSize = 0x28;
        internal const int OffDataLength = 0x00;
        internal const int OffTotalLength = 0x02;
        private const int OffType = 0x04;
        private const int OffProcessId = 0x08;
        private const int OffThreadId = 0x10;
        internal const int OffMessageId = 0x18;
        private const int OffCallbackId = 0x20;
        private const int OffMessageId32 = 0x10;
        private const int OffCallbackId32 = 0x14;
        private const ushort ThirtyTwoBitMessage = 0x1000;
        private const int MaxDataLength = 0xFFFF - HeaderSize;

        private const ushort LpcRequest = 1;
        private const ushort LpcReply = 2;
        private const ushort LpcDatagram = 3;
        private const ushort LpcPortClosed = 5;
        private const ushort LpcConnectionRequest = 10;
        private const ushort LpcConnectionReply = 11;
        private const ushort LpcCanceled = 12;
        private const ushort LpcContinuationRequired = 0x2000;
        private static readonly byte[] PortClosedData = new byte[8];

        // NT: ALPC_MESSAGE_*_ATTRIBUTE and their x64 sizes, in buffer order.
        private const uint SecurityAttribute = 0x80000000;
        private const uint ViewAttribute = 0x40000000;
        private const uint ContextAttribute = 0x20000000;
        internal const uint HandleAttribute = 0x10000000;
        private const uint TokenAttribute = 0x08000000;
        private const uint DirectAttribute = 0x04000000;
        private const uint WorkOnBehalfAttribute = 0x02000000;
        private const uint CarriedAttributes = ViewAttribute | HandleAttribute;
        internal const int AttributeHeaderSize = 8;
        internal const int HandleAttributeSize = 0x18;
        private const int SecurityAttributeSize = 0x18;
        private const int SecurityAttributeSize32 = 0x0C;
        private static readonly (uint Flag, int Size)[] AttributeSizes =
        {
            (SecurityAttribute, SecurityAttributeSize), (ViewAttribute, 0x20), (ContextAttribute, 0x20), (HandleAttribute, HandleAttributeSize),
            (TokenAttribute, 0x18), (DirectAttribute, 0x08), (WorkOnBehalfAttribute, 0x08),
        };

        // ALPC_CONTEXT_ATTR: PortContext, then MessageContext.
        private const int ContextMessageOffset = 0x08;
        private const ushort ReplyTypeFlagsMask = 0xFF00;

        private const int MaxQueuedMessages = 0x4000;
        private const int MaxReceivers = 0x400;

        private const uint ReleaseMessageFlag = 0x10000;
        internal const uint SyncRequestFlag = 0x20000;
        private const int MaxSecurityContexts = 0x10000;

        // ALPC_SECURITY_ATTR holds Flags, the QoS pointer and the context handle, each in a pointer-sized slot.
        private const int SecurityQosField = 1;
        private const int SecurityContextHandleField = 2;

        private const uint ReleaseContextFlag = 0x10000;
        private const uint CreateHandleFlag = 0x20000;
        private const uint SecurityAttributeFlags = ReleaseContextFlag | CreateHandleFlag;
        private const ulong CaptureOnSend = unchecked((ulong)-2L);

        // NT: ALPC_PORT_ATTRIBUTES on x64.
        private const int PortAttributesSize = 0x48;
        private const int OffPortAttributesQos = 4;
        private const int OffPortAttributesMaxMessageLength = 0x10;
        private const ulong MaxMessageLengthLimit = 0xFFFF;
        private const uint AllowImpersonationFlag = 0x10000;
        private const uint AcceptRequestsFlag = 0x20000;
        private const uint WaitablePortFlag = 0x40000;
        private const uint KernelOnlyPortFlag = 0x100000;

        private const int ImpersonateLevelShift = 2;
        private const ulong ImpersonateLevelGiven = 2;

        private static uint NextMessageId;
        private static uint NextCallbackId;

        internal static bool Supported(BinaryEmulator Instance) => Supported(Instance.WinHelper);

        internal static bool Supported(WinSysHelper Helper) => Helper.PointerSize == 8;

        internal static bool Owns(WinPort Port) => Port.Queue != null || Port.Connection != null;

        internal static NTSTATUS SendWaitReceive(BinaryEmulator Instance, WinPort Port, uint Flags, ulong SendMessagePtr, ulong SendAttributesPtr, ulong ReceiveMessagePtr, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            if (!Supported(Instance))
                return Unsupported(Port);

            return Port.IsClientEnd
                ? SendGuest(Instance, Port, SendMessagePtr, SendAttributesPtr, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr)
                : ServerSendWaitReceive(Instance, Port, Flags, SendMessagePtr, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr);
        }

        // NT: NtWaitForWorkViaWorkerFactory sends the message a thread pool callback left, and ignores the result.
        internal static void SendDeferred(BinaryEmulator Instance, ulong PortHandle, uint Flags, ulong MessagePtr)
        {
            WinPort Port = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle);
            if (Port == null)
                return;

            if (!Owns(Port))
            {
                Utils.LogError($"[-] ALPC: a thread pool callback leaves a message for \"{Port.Name}\", a port Brovan serves.");
                return;
            }

            SendWaitReceive(Instance, Port, Flags, MessagePtr, 0, 0, 0, 0, 0);
        }

        internal static WinPort CreateConnectionPort(string Name, uint Flags)
        {
            return new WinPort { Name = Name, Queue = new AlpcServerQueue(), WaitSemaphore = WaitSemaphoreFor(Flags) };
        }

        internal static WinPort CreateHostPort(string Name, AlpcHostServer Server)
        {
            return new WinPort { Name = Name, Queue = new AlpcServerQueue(), HostServer = Server };
        }

        private static WinSemaphore WaitSemaphoreFor(uint Flags)
        {
            return (Flags & WaitablePortFlag) != 0 ? new WinSemaphore { MaximumCount = int.MaxValue } : null;
        }

        internal static NTSTATUS TryReadPortFlags(BinaryEmulator Instance, ulong PortAttributesPtr, out uint Flags)
        {
            Flags = 0;
            return PortAttributesPtr == 0 || Instance.WinHelper.TryReadUInt32(PortAttributesPtr, out Flags) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        internal static NTSTATUS AssociateCompletionPort(BinaryEmulator Instance, WinPort Port, ulong CompletionKey, ulong CompletionHandle)
        {
            NTSTATUS Status = AssociateCompletionPort(Instance, Port.Queue, CompletionKey, CompletionHandle);
            if (Status == NTSTATUS.STATUS_SUCCESS && Instance.WinHelper.PendingConnectReplies.Count != 0)
                DeliverConnectReplyForRoute(Instance, Port, Port.Queue.CompletionPort);
            return Status;
        }

        internal static NTSTATUS AssociateCompletionPort(BinaryEmulator Instance, AlpcReceiveQueue Queue, ulong CompletionKey, ulong CompletionHandle)
        {
            WinIoCompletion Completion = Instance.WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(CompletionHandle);
            if (Completion == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            bool NewPort = Queue.CompletionPort != Completion;
            Queue.CompletionPort = Completion;
            Queue.CompletionKey = CompletionKey;

            // NT posts one completion for each message already pending on the port (AlpcpAssociateIoCompletionPort).
            for (int Index = 0; NewPort && Index < Queue.Pending.Count; Index++)
                Completion.Post(new WinIoCompletionEntry { KeyContext = CompletionKey, IoStatus = NTSTATUS.STATUS_SUCCESS });

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS ConnectGuest(BinaryEmulator Instance, WinPort ConnectionPort, ulong PortHandlePtr, ulong PortAttributesPtr, uint Flags, ulong MessagePtr, ulong BufferLengthPtr, ulong TimeoutPtr)
        {
            // CoreMessaging turns access denied from its registrar into an error and every other failure into a fail-fast.
            if (!Supported(Instance) && ConnectionPort.HostServer != null)
            {
                Utils.LogError($"[-] ALPC: \"{ConnectionPort.Name}\" is served to x64 guests only.");
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (!Supported(Instance))
                return Unsupported(ConnectionPort);

            NTSTATUS CaptureStatus = CaptureConnectingClient(Instance, PortAttributesPtr, out AlpcSecurityContext Client, out bool AllowImpersonation, out uint PortFlags);
            if (CaptureStatus != NTSTATUS.STATUS_SUCCESS)
                return CaptureStatus;

            ulong BufferLength = 0;
            if (BufferLengthPtr != 0 && !Instance.WinHelper.TryReadUInt64(BufferLengthPtr, out BufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            byte[] Data = Array.Empty<byte>();
            if (MessagePtr != 0)
            {
                NTSTATUS ReadStatus = TryReadMessage(Instance, MessagePtr, out Data, out _);
                if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                    return ReadStatus;
            }

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (IsFull(ConnectionPort.Queue))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            AlpcConnection Connection = NewConnection(Instance, ConnectionPort, Client, AllowImpersonation, Host: null);
            Connection.ClientPort = new WinPort
            {
                Connection = Connection,
                IsClientEnd = true,
                Queue = new AlpcReceiveQueue(),
                AcceptsRequests = (PortFlags & AcceptRequestsFlag) != 0,
                WaitSemaphore = WaitSemaphoreFor(PortFlags),
            };

            AlpcWait Wait = new AlpcWait
            {
                Kind = AlpcWaitKind.Connect,
                Port = Connection.ClientPort,
                PortHandlePtr = PortHandlePtr,
                MessagePtr = MessagePtr,
                BufferLength = BufferLength,
                BufferLengthPtr = BufferLengthPtr,
            };

            AlpcMessage Request = NewMessage(Instance, Connection, LpcConnectionRequest, Data);
            if (ConnectionPort.HostServer != null)
                return ConnectHostServer(Instance, ConnectionPort.HostServer, Wait, Request, (Flags & SyncRequestFlag) != 0);

            Connection.ConnectWait = Wait;
            Enqueue(Instance, ConnectionPort, Request);
            Instance.WinHelper.ParkForIoRequest(Wait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
            return NTSTATUS.STATUS_PENDING;
        }

        private static NTSTATUS ConnectHostServer(BinaryEmulator Instance, AlpcHostServer Server, AlpcWait Wait, AlpcMessage Request, bool Synchronous)
        {
            AlpcConnection Connection = Request.Connection;
            bool Accepted = false;
            byte[] Reply = null;
            object State = null;
            try
            {
                Accepted = Server.Connect(Instance, Connection, Request.Data, out Reply, out State);
            }
            catch (Exception Error)
            {
                LogServerFailure(Connection, Error);
            }

            if (!Accepted)
            {
                EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_CONNECTION_REFUSED);
                return Synchronous ? NTSTATUS.STATUS_PORT_CONNECTION_REFUSED : CompleteAsyncConnect(Instance, Wait, Request, null, Request.ProcessId, Request.ThreadId);
            }

            Connection.State = AlpcConnectionState.Connected;
            Connection.ClientReachable = true;
            Connection.HostServerState = State;
            Reply ??= Array.Empty<byte>();
            return Synchronous
                ? CompleteConnect(Instance, Wait, Request, Reply, Server.ProcessId, Server.ThreadId)
                : CompleteAsyncConnect(Instance, Wait, Request, Reply, Server.ProcessId, Server.ThreadId);
        }

        // Host.Connected runs when the server accepts or refuses, or when the connection ends first.
        internal static NTSTATUS ConnectHost(BinaryEmulator Instance, WinPort ConnectionPort, AlpcHost Host, AlpcSecurityContext Client, out AlpcConnection Connection)
        {
            Connection = null;
            if (!Supported(Instance))
                return Unsupported(ConnectionPort);

            if (ConnectionPort.HostServer != null)
            {
                Utils.LogError($"[-] ALPC: Brovan's client cannot connect to \"{ConnectionPort.Name}\", which Brovan serves itself.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            if (IsFull(ConnectionPort.Queue))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            Connection = NewConnection(Instance, ConnectionPort, Client, AllowImpersonation: true, Host);
            Enqueue(Instance, ConnectionPort, NewMessage(Instance, Connection, LpcConnectionRequest, Array.Empty<byte>()));
            return NTSTATUS.STATUS_SUCCESS;
        }

        // OnReply runs with the server's reply, or with the failure that ends the request.
        internal static NTSTATUS SendHost(BinaryEmulator Instance, AlpcConnection Connection, byte[] Data, HostReplyHandler OnReply)
        {
            if (Connection.State != AlpcConnectionState.Connected)
                return NTSTATUS.STATUS_PORT_DISCONNECTED;

            if (Data.Length > MaxDataLength)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (IsFull(Connection.ConnectionPort.Queue))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            AlpcMessage Message = NewMessage(Instance, Connection, LpcRequest, Data);
            Message.Sequence = ++Connection.NextSequence;
            Message.HostReply = OnReply;
            Connection.AwaitingReply.Add(Message);
            Enqueue(Instance, Connection.ConnectionPort, Message);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS CreateSecurityContext(BinaryEmulator Instance, ulong PortHandle, uint Flags, ulong AttributePtr)
        {
            if (Flags != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if ((AttributePtr & (PointerSize - 1)) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            // NT probes the attribute for write before the capture.
            Span<byte> Attribute = stackalloc byte[PointerSize == 8 ? SecurityAttributeSize : SecurityAttributeSize32];
            if (!Instance.ReadMemory(AttributePtr, Attribute) || !Instance.WriteMemory(AttributePtr, Attribute))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Qos = stackalloc byte[SecurityQos.Size];
            if (!TryReadAttributeQos(Instance, Attribute, PointerSize, ref Qos))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(PortHandle, AccessMask.None, out WinPort Port, out ulong PortKey, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = CaptureForAttribute(Instance, Port, Qos, out AlpcSecurityContext Context);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return InsertContext(Instance, Port, ServedClientOf(Port, PortKey), Context, AttributePtr + SecurityContextHandleField * PointerSize);
        }

        private static bool TryReadAttributeQos(BinaryEmulator Instance, ReadOnlySpan<byte> Attribute, uint PointerSize, ref Span<byte> Qos)
        {
            ulong QosPtr = WinSysHelper.ReadPointerField(Attribute, SecurityQosField, PointerSize);
            if (QosPtr == 0)
                Qos = default;
            return QosPtr == 0 || Instance.ReadMemory(QosPtr, Qos);
        }

        private static NTSTATUS InsertContext(BinaryEmulator Instance, WinPort Port, ServedClient? Served, AlpcSecurityContext Context, ulong HandlePtr)
        {
            Port.SecurityContexts ??= new Dictionary<ulong, AlpcSecurityContext>();
            if (Port.SecurityContexts.Count >= MaxSecurityContexts)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            Context.Owner = Port;
            Context.Served = Served;
            Context.Handle = ++Port.NextSecurityContext;
            Port.SecurityContexts[Context.Handle] = Context;
            if (Instance.WinHelper.WritePointer(HandlePtr, Context.Handle))
                return NTSTATUS.STATUS_SUCCESS;

            Port.SecurityContexts.Remove(Context.Handle);
            return NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static AlpcSecurityContext FindContext(WinPort Port, ulong Handle, ServedClient? Served = null)
        {
            return Port.SecurityContexts != null && Port.SecurityContexts.TryGetValue(Handle, out AlpcSecurityContext Context)
                && Context.Served == Served ? Context : null;
        }

        // NT keeps a deleted context in the table until the last queued message that carries it goes (AlpcpDeleteBlob).
        private static bool DeleteContext(AlpcSecurityContext Context)
        {
            if (Context.Deleted)
                return false;

            Context.Deleted = true;
            RemoveIfUnused(Context);
            return true;
        }

        private static void ReleaseContext(AlpcMessage Message)
        {
            AlpcSecurityContext Context = Message.SecurityContext;
            if (Context == null)
                return;

            Message.SecurityContext = null;
            Context.Messages--;
            RemoveIfUnused(Context);
        }

        private static void RemoveIfUnused(AlpcSecurityContext Context)
        {
            if (Context.Deleted && Context.Messages == 0)
                Context.Owner.SecurityContexts.Remove(Context.Handle);
        }

        // A served port is one object, so a handle stands for one client and its duplicates share that client.
        internal static ServedClient ServedClientOf(WinPort Port, ulong HandleKey)
        {
            return Port.Handler == null ? null : ClientOfHandle(Port, HandleKey);
        }

        internal static void ShareServedClient(WinPort Port, ulong SourceKey, ulong DuplicateKey)
        {
            if (Port.Handler == null)
                return;

            ServedClient Client = ClientOfHandle(Port, SourceKey);
            Client.Handles++;
            Port.ServedClients[DuplicateKey] = Client;
        }

        internal static void ReleaseServedClient(BinaryEmulator Instance, WinPort Port, ulong HandleKey)
        {
            if (Port.ServedClients == null || !Port.ServedClients.Remove(HandleKey, out ServedClient Client) || --Client.Handles > 0)
                return;

            if (Client.Queue != null && EndReceivers(Client.Queue))
                Instance.WakeSignal.Bump();

            if (Port.SecurityContexts == null)
                return;

            foreach (KeyValuePair<ulong, AlpcSecurityContext> Entry in Port.SecurityContexts)
            {
                if (Entry.Value.Served == Client)
                    Port.SecurityContexts.Remove(Entry.Key);
            }
        }

        internal static AlpcReceiveQueue? ServedQueueOf(WinPort Port, ulong HandleKey) => Port.ServedClients?.GetValueOrDefault(HandleKey)?.Queue;

        internal static AlpcReceiveQueue EnsureServedQueue(WinPort Port, ulong HandleKey) => ClientOfHandle(Port, HandleKey).Queue ??= new AlpcReceiveQueue();

        private static ServedClient ClientOfHandle(WinPort Port, ulong HandleKey)
        {
            Port.ServedClients ??= new Dictionary<ulong, ServedClient>();
            ref ServedClient Client = ref CollectionsMarshal.GetValueRefOrAddDefault(Port.ServedClients, HandleKey, out _);
            Client ??= new ServedClient();
            return Client;
        }

        internal static NTSTATUS DeleteSecurityContext(BinaryEmulator Instance, ulong PortHandle, uint Flags, ulong ContextHandle)
        {
            if (Flags != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(PortHandle, AccessMask.None, out WinPort Port, out ulong PortKey, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            AlpcSecurityContext Context = FindContext(Port, ContextHandle, Port.ServedClients?.GetValueOrDefault(PortKey));
            if (Context == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            return DeleteContext(Context) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_DELETE_PENDING;
        }

        private static NTSTATUS TryReadMessageIds(BinaryEmulator Instance, ulong MessagePtr, out uint MessageId, out uint CallbackId)
        {
            MessageId = 0;
            CallbackId = 0;
            if ((MessagePtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Header = stackalloc byte[HeaderSize];
            if (!Instance.ReadMemory(MessagePtr, Header))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool ThirtyTwoBit = (BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(OffType)) & ThirtyTwoBitMessage) != 0;
            MessageId = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(ThirtyTwoBit ? OffMessageId32 : OffMessageId));
            CallbackId = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(ThirtyTwoBit ? OffCallbackId32 : OffCallbackId));
            return MessageId == 0 ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS ImpersonateClient(BinaryEmulator Instance, ulong PortHandle, ulong MessagePtr, ulong Flags)
        {
            uint MessageId = 0;
            uint CallbackId = 0;
            if (MessagePtr != 0)
            {
                NTSTATUS ReadStatus = TryReadMessageIds(Instance, MessagePtr, out MessageId, out CallbackId);
                if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                    return ReadStatus;
            }

            ulong RequestedLevel = Flags >> ImpersonateLevelShift;
            if (RequestedLevel > (ulong)SecurityImpersonationLevel.SecurityDelegation)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            bool LevelGiven = RequestedLevel != 0 || (Flags & ImpersonateLevelGiven) != 0;

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(PortHandle, AccessMask.None, out WinPort Port);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            AlpcConnection Connection = Port.IsClientEnd ? null : Port.Connection;
            AlpcSecurityContext Context;
            WinToken ClientToken;
            if (MessagePtr == 0)
            {
                if (Connection == null || Connection.State != AlpcConnectionState.Connected || !Connection.AllowImpersonation || Connection.Client.Qos.DynamicTracking)
                    return NTSTATUS.STATUS_ACCESS_DENIED;
                Context = Connection.Client;
                ClientToken = Context.Token;
            }
            else
            {
                AlpcServerQueue Queue = Port.ServerQueue ?? Port.Connection?.ConnectionPort.ServerQueue;
                if (Queue == null || !Queue.Delivered.TryGetValue(MessageId, out AlpcMessage Message) || (CallbackId != 0 && Message.CallbackId != CallbackId))
                    return NTSTATUS.STATUS_INVALID_MESSAGE;

                if (Connection != Message.Connection)
                    return NTSTATUS.STATUS_ACCESS_DENIED;

                if (Message.SecurityContext == null && !Connection.AllowImpersonation)
                    return NTSTATUS.STATUS_ACCESS_DENIED;

                // A message carries a sender token only on a connection with dynamic tracking.
                Context = Message.SecurityContext ?? Connection.Client;
                ClientToken = Message.SecurityContext?.Token ?? Message.SenderToken ?? Connection.Client.Token;
            }

            SecurityImpersonationLevel Level = Context.Qos.Level;
            if (LevelGiven)
            {
                if (RequestedLevel > (ulong)Level)
                    return NTSTATUS.STATUS_ACCESS_DENIED;
                Level = (SecurityImpersonationLevel)RequestedLevel;
            }

            if (ClientToken == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            WindowsThreadState State = WinEmulatedThread.GetState(Instance.CurrentThread);
            SecurityImpersonationLevel Permitted = NtQueryInformationToken.PermittedImpersonationLevel(Instance, ClientToken, Level);
            State.ImpersonationToken = ClientToken.Duplicate(TokenType.Impersonation, Permitted, Context.Qos.EffectiveOnly);
            State.ImpersonationTokenHandle = 0;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS Accept(BinaryEmulator Instance, WinPort ConnectionPort, ulong PortHandlePtr, ulong PortAttributesPtr, ulong PortContext, ulong MessagePtr, bool AcceptConnection)
        {
            if (!Supported(Instance))
                return Unsupported(ConnectionPort);

            if (MessagePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS FlagsStatus = TryReadPortFlags(Instance, PortAttributesPtr, out uint PortFlags);
            if (FlagsStatus != NTSTATUS.STATUS_SUCCESS)
                return FlagsStatus;

            NTSTATUS ReadStatus = TryReadAnswer(Instance, MessagePtr, out uint MessageId, out Span<byte> Data);
            if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                return ReadStatus;

            AlpcServerQueue Queue = ConnectionPort.ServerQueue;
            if (!Queue.Delivered.TryGetValue(MessageId, out AlpcMessage Request) || Request.Type != LpcConnectionRequest)
                return NTSTATUS.STATUS_INVALID_MESSAGE;

            AlpcConnection Connection = Request.Connection;
            if (!AcceptConnection)
            {
                Queue.Delivered.Remove(MessageId);
                EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_CONNECTION_REFUSED);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (PortHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            AlpcWait Wait = Connection.ConnectWait;
            bool ClientWaits = Connection.Host != null ? Connection.State == AlpcConnectionState.Connecting : Wait != null && Wait.IsLive;
            if (!ClientWaits)
            {
                Queue.Delivered.Remove(MessageId);
                EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
                return NTSTATUS.STATUS_PORT_DISCONNECTED;
            }

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(new WinPort { Connection = Connection, WaitSemaphore = WaitSemaphoreFor(PortFlags) }, AccessMask.StandardRightsAll);
            if (!Instance.WinHelper.WritePointer(PortHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Queue.Delivered.Remove(MessageId);
            Connection.PortContext = PortContext;
            Connection.State = AlpcConnectionState.Connected;
            Connection.ClientReachable = Connection.ClientPort != null;
            Connection.ConnectWait = null;
            if (Connection.Host != null)
                RunConnected(Connection.Host, NTSTATUS.STATUS_SUCCESS);
            else
                Wait.Complete(Instance, CompleteConnect(Instance, Wait, Request, Data, Instance.WinHelper.PID, CurrentThreadId(Instance)));

            return NTSTATUS.STATUS_SUCCESS;
        }

        // Runs when the last handle to the port closes.
        internal static void PortClosed(BinaryEmulator Instance, WinPort Port)
        {
            AlpcConnection Connection = Port.Connection;
            if (Connection != null)
            {
                if (Port.IsClientEnd)
                    CloseClient(Instance, Connection);
                else
                    CloseServer(Instance, Connection);
                return;
            }

            AlpcServerQueue Queue = Port.ServerQueue;
            if (Queue == null)
                return;

            bool Woke = EndReceivers(Queue);
            foreach (AlpcMessage Received in Queue.Delivered.Values)
                ReleaseContext(Received);

            // A host callback can end other connections of this queue.
            int OpenCount = Queue.Connections.Count;
            AlpcConnection[] Open = ArrayPool<AlpcConnection>.Shared.Rent(OpenCount);
            Queue.Connections.CopyTo(Open);
            Queue.Connections.Clear();
            Queue.Delivered.Clear();

            try
            {
                for (int Index = 0; Index < OpenCount; Index++)
                {
                    DropConnectReply(Instance, Open[Index]);
                    Woke |= EndWaits(Open[Index], NTSTATUS.STATUS_PORT_DISCONNECTED);
                }
            }
            finally
            {
                ArrayPool<AlpcConnection>.Shared.Return(Open, clearArray: true);
            }

            if (Woke)
                Instance.WakeSignal.Bump();
        }

        private static bool EndReceivers(AlpcReceiveQueue Queue)
        {
            bool Woke = false;
            foreach (AlpcWait Receiver in Queue.Receivers)
                Woke |= FinishIfLive(Receiver, NTSTATUS.STATUS_PORT_DISCONNECTED);

            foreach (AlpcMessage Queued in Queue.Pending)
                ReleaseContext(Queued);

            Queue.Receivers.Clear();
            Queue.Pending.Clear();
            Queue.CompletionPort = null;
            return Woke;
        }

        internal static ulong AttributeOffset(uint Allocated, uint Flag)
        {
            ulong Offset = AttributeHeaderSize;
            foreach ((uint Bit, int Size) in AttributeSizes)
            {
                if (Bit == Flag)
                    break;
                if ((Allocated & Bit) != 0)
                    Offset += (ulong)Size;
            }

            return Offset;
        }

        private static NTSTATUS Unsupported(WinPort Port)
        {
            Utils.LogError($"[-] ALPC: \"{Port.Name}\" is a port of this process; messages between guest ports are x64 only.");
            return NTSTATUS.STATUS_NOT_SUPPORTED;
        }

        private static NTSTATUS SendGuest(BinaryEmulator Instance, WinPort ClientPort, ulong SendMessagePtr, ulong SendAttributesPtr, ulong ReceiveMessagePtr, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            AlpcConnection Connection = ClientPort.Connection;
            if (SendMessagePtr == 0)
                return ReceiveMessagePtr == 0 ? NTSTATUS.STATUS_SUCCESS : ReceivePort(Instance, ClientPort, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr);

            if (Connection.PendingConnectReply != null)
                return NTSTATUS.STATUS_LPC_REQUESTS_NOT_ALLOWED;

            if (Connection.State != AlpcConnectionState.Connected)
                return NTSTATUS.STATUS_PORT_DISCONNECTED;

            ulong SecurityAttributePtr = 0;
            ulong SendHeader = 0;
            if (SendAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadUInt64(SendAttributesPtr, out SendHeader))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint SendValid = (uint)(SendHeader >> 32);

                if ((SendValid & CarriedAttributes) != 0)
                {
                    Utils.LogError($"[-] ALPC: a client of \"{Connection.ConnectionPort.Name}\" sends attributes 0x{SendValid:X8}; views and handles do not travel between ports of this process.");
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                }

                if ((SendValid & SecurityAttribute) != 0)
                    SecurityAttributePtr = SendAttributesPtr + AttributeOffset((uint)SendHeader, SecurityAttribute);
            }

            NTSTATUS ReadStatus = TryReadMessage(Instance, SendMessagePtr, out byte[] Data, out ushort TypeFlags);
            if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                return ReadStatus;

            bool WaitsForReply = ReceiveMessagePtr != 0;
            ulong BufferLength = 0;
            if (WaitsForReply)
            {
                if (BufferLengthPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.WinHelper.TryReadUInt64(BufferLengthPtr, out BufferLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            AlpcHostServer HostServer = Connection.ConnectionPort.HostServer;
            ulong MessageContext = 0;
            if (HostServer != null)
            {
                NTSTATUS ContextStatus = ReadMessageContext(Instance, SendAttributesPtr, SendHeader, out MessageContext);
                if (ContextStatus != NTSTATUS.STATUS_SUCCESS)
                    return ContextStatus;
            }

            if (IsFull(Connection.ConnectionPort.Queue) || (HostServer != null && !WaitsForReply && IsFull(ClientPort.Queue)))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            AlpcSecurityContext SecurityContext = null;
            if (SecurityAttributePtr != 0)
            {
                NTSTATUS SecurityStatus = CaptureSendSecurity(Instance, ClientPort, SecurityAttributePtr, out SecurityContext);
                if (SecurityStatus != NTSTATUS.STATUS_SUCCESS)
                    return SecurityStatus;
            }

            AlpcMessage Message = NewMessage(Instance, Connection, LpcRequest, Data);
            Message.Sequence = ++Connection.NextSequence;
            Message.SecurityContext = SecurityContext;
            if (SecurityContext != null)
                SecurityContext.Messages++;
            if (WaitsForReply)
            {
                Message.ReplyWait = new AlpcWait
                {
                    Kind = AlpcWaitKind.Reply,
                    MessagePtr = ReceiveMessagePtr,
                    BufferLength = BufferLength,
                    BufferLengthPtr = BufferLengthPtr,
                    AttributesPtr = ReceiveAttributesPtr,
                };
            }

            if (HostServer != null)
                return SendHostServer(Instance, HostServer, Message, new AlpcRequestFacts(TypeFlags, Message.CallbackId, MessageContext));

            if (WaitsForReply)
                Connection.AwaitingReply.Add(Message);

            Enqueue(Instance, Connection.ConnectionPort, Message);
            if (!WaitsForReply)
                return NTSTATUS.STATUS_SUCCESS;

            Instance.WinHelper.ParkForIoRequest(Message.ReplyWait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
            return NTSTATUS.STATUS_PENDING;
        }

        private static NTSTATUS SendHostServer(BinaryEmulator Instance, AlpcHostServer Server, AlpcMessage Message, in AlpcRequestFacts Facts)
        {
            AlpcWait Wait = Message.ReplyWait;
            NTSTATUS Status = NTSTATUS.STATUS_UNSUCCESSFUL;
            byte[] Reply = null;
            try
            {
                Status = Server.Receive(Instance, Message.Connection, Message.Data, Wait != null, out Reply);
            }
            catch (Exception Error)
            {
                LogServerFailure(Message.Connection, Error);
            }
            finally
            {
                ReleaseContext(Message);
            }

            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Wait == null)
            {
                WinPort ClientPort = Message.Connection.ClientPort;
                if (Reply != null && HasAnswerRoute(ClientPort.Queue, ClientPort.WaitSemaphore))
                    QueueReply(Instance, ClientPort.Queue, ClientPort.WaitSemaphore, Facts, Reply, Server.ProcessId, Server.ThreadId);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Reply == null)
            {
                Utils.LogError($"[-] ALPC: Brovan's server of \"{Message.Connection.ConnectionPort.Name}\" left a request without a reply.");
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            return WriteReply(Instance, Wait, LpcReply, Facts.TypeFlags, Message, Reply, Server.ProcessId, Server.ThreadId);
        }

        internal static NTSTATUS QueueHandlerReply(BinaryEmulator Instance, WinPort Port, AlpcReceiveQueue Queue, in AlpcRequestFacts Facts, byte[] Reply)
        {
            if (Reply.Length < HeaderSize || Reply.Length - HeaderSize > MaxDataLength)
            {
                Utils.LogError($"[-] ALPC: the handler of \"{Port.Name}\" answered a send that does not wait with {Reply.Length} bytes.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            QueueReply(Instance, Queue, null, Facts, Reply.AsSpan(HeaderSize).ToArray(), BinaryPrimitives.ReadUInt64LittleEndian(Reply.AsSpan(OffProcessId)),
                BinaryPrimitives.ReadUInt64LittleEndian(Reply.AsSpan(OffThreadId)));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void QueueReply(BinaryEmulator Instance, AlpcReceiveQueue Queue, WinSemaphore WaitSemaphore, in AlpcRequestFacts Facts, byte[] Data,
            ulong ProcessId, ulong ThreadId)
        {
            Enqueue(Instance, Queue, WaitSemaphore, new AlpcMessage
            {
                Type = LpcReply,
                TypeFlags = Facts.TypeFlags,
                Data = Data,
                ProcessId = ProcessId,
                ThreadId = ThreadId,
                MessageId = TakeId(ref NextMessageId),
                CallbackId = Facts.CallbackId,
                MessageContext = Facts.MessageContext,
            });
        }

        internal static bool QueuesAnswers(WinPort Port) => Port.IsClientEnd && Port.Connection.ConnectionPort.HostServer != null;

        // A send with no route for its answer gets none, as a one-way call does, so unclaimed answers do not pile up.
        internal static bool HasAnswerRoute(AlpcReceiveQueue Queue, WinSemaphore? WaitSemaphore)
        {
            if (Queue.CompletionPort != null || WaitSemaphore != null)
                return true;

            for (int Index = 0; Index < Queue.Receivers.Count; Index++)
            {
                if (Queue.Receivers[Index].IsLive)
                    return true;
            }

            return false;
        }

        internal static uint NewCallbackId() => TakeId(ref NextCallbackId);

        internal static ushort TypeFlagsOf(ReadOnlySpan<byte> Header) => (ushort)(BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(OffType)) & ReplyTypeFlagsMask);

        internal static NTSTATUS ReadMessageContext(BinaryEmulator Instance, ulong SendAttributesPtr, ulong AttributeHeader, out ulong MessageContext)
        {
            MessageContext = 0;
            uint Allocated = (uint)AttributeHeader;
            uint Valid = (uint)(AttributeHeader >> 32);
            if (SendAttributesPtr != 0 && (Valid & ContextAttribute) != 0
                && !Instance.WinHelper.TryReadUInt64(SendAttributesPtr + AttributeOffset(Allocated, ContextAttribute) + ContextMessageOffset, out MessageContext))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ServerSendWaitReceive(BinaryEmulator Instance, WinPort Port, uint Flags, ulong SendMessagePtr, ulong ReceiveMessagePtr, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            if (SendMessagePtr != 0)
            {
                NTSTATUS SendStatus = ServerSend(Instance, Port, Flags, SendMessagePtr, ReceiveMessagePtr != 0);
                if (SendStatus != NTSTATUS.STATUS_SUCCESS)
                    return SendStatus;
            }

            if (ReceiveMessagePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (!Port.IsServer)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            return ReceivePort(Instance, Port, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr);
        }

        // NT: a send replies to the request with the same message id, and a zero id sends the client a new message.
        private static NTSTATUS ServerSend(BinaryEmulator Instance, WinPort Port, uint Flags, ulong MessagePtr, bool WaitsForReply)
        {
            NTSTATUS ReadStatus = TryReadAnswer(Instance, MessagePtr, out uint MessageId, out Span<byte> Data);
            if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                return ReadStatus;

            AlpcConnection Connection = Port.Connection;
            if (MessageId == 0 && Connection != null)
                return SendToClient(Instance, Connection, Flags, Data, WaitsForReply);

            return Reply(Instance, Port.ServerQueue ?? Connection.ConnectionPort.ServerQueue, Flags, MessageId, Data);
        }

        private static NTSTATUS SendToClient(BinaryEmulator Instance, AlpcConnection Connection, uint Flags, ReadOnlySpan<byte> Data, bool WaitsForReply)
        {
            WinPort ClientPort = Connection.ClientPort;
            if (ClientPort == null || WaitsForReply)
            {
                Utils.LogError($"[-] ALPC: the server of \"{Connection.ConnectionPort.Name}\" sends {(WaitsForReply ? "a request" : "a message")} to {(ClientPort == null ? "Brovan's client" : "its client")}, which ports of this process do not deliver.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            return PostToClient(Instance, Connection, (Flags & ReleaseMessageFlag) != 0, Data.ToArray(), Instance.WinHelper.PID, CurrentThreadId(Instance));
        }

        internal static bool SendFromHostServer(BinaryEmulator Instance, AlpcHostServer Server, AlpcConnection Connection, byte[] Data)
        {
            NTSTATUS Status = Data.Length > MaxDataLength ? NTSTATUS.STATUS_INVALID_PARAMETER : PostToClient(Instance, Connection, true, Data, Server.ProcessId, Server.ThreadId);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                return true;

            Utils.LogError($"[-] ALPC: Brovan's server of \"{Connection.ConnectionPort.Name}\" could not send {Data.Length} bytes to its client: 0x{(uint)Status:X8}.");
            return false;
        }

        private static NTSTATUS PostToClient(BinaryEmulator Instance, AlpcConnection Connection, bool Released, byte[] Data, ulong ProcessId, ulong ThreadId)
        {
            WinPort ClientPort = Connection.ClientPort;
            if (!Connection.ClientReachable)
                return NTSTATUS.STATUS_PORT_DISCONNECTED;

            if (!ClientPort.AcceptsRequests)
                return NTSTATUS.STATUS_LPC_REQUESTS_NOT_ALLOWED;

            if (IsFull(ClientPort.Queue))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            FlushConnectReply(Instance, Connection);
            Enqueue(Instance, ClientPort, new AlpcMessage
            {
                Type = Released ? LpcDatagram : LpcRequest,
                TypeFlags = Released ? (ushort)0 : LpcContinuationRequired,
                Data = Data,
                ProcessId = ProcessId,
                ThreadId = ThreadId,
                MessageId = TakeId(ref NextMessageId),
                CallbackId = TakeId(ref NextCallbackId),
                Sequence = ++Connection.NextClientSequence,
                Connection = Connection,
            });
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReceivePort(BinaryEmulator Instance, WinPort Port, ulong ReceiveMessagePtr, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr) =>
            ReceiveFrom(Instance, Port.Queue, Port.WaitSemaphore, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr);

        internal static NTSTATUS ReceiveFrom(BinaryEmulator Instance, AlpcReceiveQueue Queue, WinSemaphore WaitSemaphore, ulong ReceiveMessagePtr, ulong BufferLengthPtr,
            ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            if (BufferLengthPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.TryReadUInt64(BufferLengthPtr, out ulong BufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Queue.Pending.Count > 0)
            {
                AlpcMessage Message = Queue.Pending.Peek();
                NTSTATUS Status = WriteReceived(Instance, Queue, Message, ReceiveMessagePtr, BufferLength, BufferLengthPtr, ReceiveAttributesPtr);
                if (Status == NTSTATUS.STATUS_SUCCESS)
                    Queue.Pending.Dequeue();
                return Status;
            }

            // NT: a receive never waits on a port that has a completion port or is waitable.
            if (Queue.CompletionPort != null || WaitSemaphore != null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            long Deadline = Instance.WinHelper.ParseRelativeDeadlineMs(Timeout);
            if (Deadline == Instance.EmulatedTickCount64)
                return NTSTATUS.STATUS_TIMEOUT;

            Queue.Receivers.RemoveAll(Receiver => !Receiver.IsLive);
            if (Queue.Receivers.Count >= MaxReceivers)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            AlpcWait Wait = new AlpcWait
            {
                Kind = AlpcWaitKind.Receive,
                MessagePtr = ReceiveMessagePtr,
                BufferLength = BufferLength,
                BufferLengthPtr = BufferLengthPtr,
                AttributesPtr = ReceiveAttributesPtr,
            };

            Queue.Receivers.Add(Wait);
            Instance.WinHelper.ParkForIoRequest(Wait, Deadline);
            return NTSTATUS.STATUS_PENDING;
        }

        private static AlpcConnection NewConnection(BinaryEmulator Instance, WinPort ConnectionPort, AlpcSecurityContext Client, bool AllowImpersonation, AlpcHost Host)
        {
            WinToken ClientToken = Client.Token;
            AlpcConnection Connection = new AlpcConnection
            {
                ConnectionPort = ConnectionPort,
                State = AlpcConnectionState.Connecting,
                TokenId = NtAllocateLocallyUniqueId.Allocate(),
                ClosedCallbackId = TakeId(ref NextCallbackId),
                Host = Host,
                Client = Client,
                ClientAuthenticationId = NtQueryInformationToken.AuthenticationIdOf(Instance, ClientToken != null ? NtQueryInformationToken.OwnerOf(Instance, ClientToken) : null),
                AllowImpersonation = AllowImpersonation,
            };

            ConnectionPort.ServerQueue.Connections.Add(Connection);
            return Connection;
        }

        // NT captures a static client at connect, but not a dynamic one (AlpcpCreateClientPort).
        private static NTSTATUS CaptureConnectingClient(BinaryEmulator Instance, ulong PortAttributesPtr, out AlpcSecurityContext Client, out bool AllowImpersonation, out uint Flags)
        {
            Client = null;
            AllowImpersonation = true;
            Flags = 0;
            SecurityQos Qos = new SecurityQos(SecurityImpersonationLevel.SecurityAnonymous, DynamicTracking: true, EffectiveOnly: true);
            if (PortAttributesPtr != 0)
            {
                Span<byte> Attributes = stackalloc byte[PortAttributesSize];
                if (!Instance.ReadMemory(PortAttributesPtr, Attributes))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Flags = BinaryPrimitives.ReadUInt32LittleEndian(Attributes);
                ulong MaxMessageLength = BinaryPrimitives.ReadUInt64LittleEndian(Attributes.Slice(OffPortAttributesMaxMessageLength));
                if (MaxMessageLength < HeaderSize || MaxMessageLength > MaxMessageLengthLimit || (Flags & KernelOnlyPortFlag) != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                NTSTATUS Status = SecurityQos.Read(Attributes.Slice(OffPortAttributesQos, SecurityQos.Size), out Qos);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                AllowImpersonation = (Flags & AllowImpersonationFlag) != 0;
            }

            if (!Qos.DynamicTracking)
                return CaptureClient(Instance, Qos, out Client);

            Client = new AlpcSecurityContext { Token = NtQueryInformationToken.EffectiveToken(Instance), Qos = Qos };
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CaptureForAttribute(BinaryEmulator Instance, WinPort Port, ReadOnlySpan<byte> RawQos, out AlpcSecurityContext Context)
        {
            Context = null;
            SecurityQos Qos = Port.Connection?.Client.Qos ?? default;
            if (!RawQos.IsEmpty)
            {
                NTSTATUS Status = SecurityQos.Read(RawQos, out Qos);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            return CaptureClient(Instance, Qos, out Context);
        }

        private static NTSTATUS CaptureClient(BinaryEmulator Instance, SecurityQos Requested, out AlpcSecurityContext Context)
        {
            Context = null;
            bool EffectiveOnly = Requested.EffectiveOnly;
            WinToken Token = NtQueryInformationToken.CallerImpersonationToken(Instance);
            if (Token != null)
            {
                if (Requested.Level > Token.ImpersonationLevel || Token.ImpersonationLevel < SecurityImpersonationLevel.SecurityImpersonation)
                    return NTSTATUS.STATUS_BAD_IMPERSONATION_LEVEL;

                EffectiveOnly |= Token.EffectiveOnly;
            }
            else
            {
                Token = Instance.WinHelper.OwnProcess?.GetPrimaryToken();
            }

            Context = new AlpcSecurityContext
            {
                Token = Requested.DynamicTracking ? Token : Token?.Duplicate(TokenType.Impersonation, Requested.Level, EffectiveOnly),
                Qos = Requested with { EffectiveOnly = EffectiveOnly },
            };
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CaptureSendSecurity(BinaryEmulator Instance, WinPort ClientPort, ulong AttributePtr, out AlpcSecurityContext Context)
        {
            Context = null;
            Span<byte> Attribute = stackalloc byte[SecurityAttributeSize];
            if (!Instance.ReadMemory(AttributePtr, Attribute))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Attribute);
            ulong Handle = WinSysHelper.ReadPointerField(Attribute, SecurityContextHandleField, sizeof(ulong));
            Span<byte> Qos = stackalloc byte[SecurityQos.Size];
            if (!TryReadAttributeQos(Instance, Attribute, sizeof(ulong), ref Qos))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Flags & ~SecurityAttributeFlags) != 0 || (Flags & SecurityAttributeFlags) == SecurityAttributeFlags)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Handle != CaptureOnSend)
            {
                Context = FindContext(ClientPort, Handle);
                if (Context == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if ((Flags & ReleaseContextFlag) != 0)
                {
                    DeleteContext(Context);
                    Context = null;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }

            if ((Flags & ReleaseContextFlag) != 0)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            NTSTATUS Status = CaptureForAttribute(Instance, ClientPort, Qos, out Context);
            if (Status != NTSTATUS.STATUS_SUCCESS || (Flags & CreateHandleFlag) == 0)
                return Status;

            return InsertContext(Instance, ClientPort, Served: null, Context, AttributePtr + SecurityContextHandleField * sizeof(ulong));
        }

        private static AlpcMessage NewMessage(BinaryEmulator Instance, AlpcConnection Connection, ushort Type, byte[] Data)
        {
            return new AlpcMessage
            {
                Type = Type,
                TypeFlags = LpcContinuationRequired,
                Data = Data,
                ProcessId = Connection.Host?.ProcessId ?? Instance.WinHelper.PID,
                ThreadId = Connection.Host?.ThreadId ?? CurrentThreadId(Instance),
                MessageId = TakeId(ref NextMessageId),
                CallbackId = TakeId(ref NextCallbackId),
                Connection = Connection,
                SenderToken = Connection.Client.Qos.DynamicTracking ? NtQueryInformationToken.EffectiveToken(Instance) : null,
            };
        }

        internal static void CloseClient(BinaryEmulator Instance, AlpcConnection Connection)
        {
            bool NotifyServer = Connection.State == AlpcConnectionState.Connected;
            DropConnectReply(Instance, Connection);
            Connection.ClientReachable = false;
            EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
            if (Connection.ClientPort != null && EndReceivers(Connection.ClientPort.Queue))
                Instance.WakeSignal.Bump();

            if (!NotifyServer)
                return;

            AlpcHostServer Server = Connection.ConnectionPort.HostServer;
            if (Server == null)
            {
                Enqueue(Instance, Connection.ConnectionPort, ClosedMessage(Connection, ++Connection.NextSequence));
                return;
            }

            try
            {
                Server.Disconnected(Instance, Connection);
            }
            catch (Exception Error)
            {
                LogServerFailure(Connection, Error);
            }

            Connection.HostServerState = null;
        }

        private static void CloseServer(BinaryEmulator Instance, AlpcConnection Connection)
        {
            bool NotifyClient = Connection.ClientReachable;
            Connection.ClientReachable = false;
            EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
            if (NotifyClient)
                Enqueue(Instance, Connection.ClientPort, ClosedMessage(Connection, ++Connection.NextClientSequence));
        }

        private static AlpcMessage ClosedMessage(AlpcConnection Connection, uint Sequence)
        {
            return new AlpcMessage
            {
                Type = LpcPortClosed,
                Data = PortClosedData,
                MessageId = TakeId(ref NextMessageId),
                CallbackId = Connection.ClosedCallbackId,
                Sequence = Sequence,
                Connection = Connection,
            };
        }

        private static void EndConnection(BinaryEmulator Instance, AlpcConnection Connection, NTSTATUS Status)
        {
            if (Connection.State == AlpcConnectionState.Closed)
                return;

            AlpcServerQueue Queue = Connection.ConnectionPort.ServerQueue;
            Queue.Connections.Remove(Connection);
            int Datagrams = Connection.DeliveredDatagrams;
            if (Datagrams != 0)
            {
                foreach (KeyValuePair<uint, AlpcMessage> Entry in Queue.Delivered)
                {
                    if (Entry.Value.Connection != Connection || !IsDatagram(Entry.Value))
                        continue;

                    Queue.Delivered.Remove(Entry.Key);
                    ReleaseContext(Entry.Value);
                    if (--Datagrams == 0)
                        break;
                }

                Connection.DeliveredDatagrams = 0;
            }

            if (EndWaits(Connection, Status))
                Instance.WakeSignal.Bump();
        }

        // A port holds a message from its send until it is received and then accepted, replied to or released.
        internal static bool IsFull(AlpcReceiveQueue Queue) => Queue.Pending.Count + ((Queue as AlpcServerQueue)?.Delivered.Count ?? 0) >= MaxQueuedMessages;

        private static bool IsDatagram(AlpcMessage Message) => Message.Type == LpcRequest && !Message.WaitsForReply;

        // Host callbacks run after the state change, so a send from one of them fails as disconnected.
        private static bool EndWaits(AlpcConnection Connection, NTSTATUS Status)
        {
            bool WasConnecting = Connection.State == AlpcConnectionState.Connecting;
            Connection.State = AlpcConnectionState.Closed;
            bool Woke = FinishIfLive(Connection.ConnectWait, Status);
            Connection.ConnectWait = null;
            if (WasConnecting && Connection.Host != null)
                RunConnected(Connection.Host, Status);

            for (int Index = 0; Index < Connection.AwaitingReply.Count; Index++)
            {
                AlpcMessage Waiting = Connection.AwaitingReply[Index];
                if (Waiting.HostReply != null)
                    RunHost(Waiting.HostReply, NTSTATUS.STATUS_PORT_DISCONNECTED, default);
                else
                    Woke |= FinishIfLive(Waiting.ReplyWait, NTSTATUS.STATUS_PORT_DISCONNECTED);
            }

            Connection.AwaitingReply.Clear();
            return Woke;
        }

        private static void Enqueue(BinaryEmulator Instance, WinPort Port, AlpcMessage Message) => Enqueue(Instance, Port.Queue, Port.WaitSemaphore, Message);

        private static void Enqueue(BinaryEmulator Instance, AlpcReceiveQueue Queue, WinSemaphore WaitSemaphore, AlpcMessage Message)
        {
            while (Queue.Receivers.Count > 0)
            {
                AlpcWait Receiver = Queue.Receivers[0];
                Queue.Receivers.RemoveAt(0);
                if (!Receiver.IsLive)
                    continue;

                NTSTATUS Status = WriteReceived(Instance, Queue, Message, Receiver.MessagePtr, Receiver.BufferLength, Receiver.BufferLengthPtr, Receiver.AttributesPtr);
                Receiver.Complete(Instance, Status);
                if (Status == NTSTATUS.STATUS_SUCCESS)
                    return;
            }

            Queue.Pending.Enqueue(Message);
            Queue.CompletionPort?.Post(new WinIoCompletionEntry { KeyContext = Queue.CompletionKey, IoStatus = NTSTATUS.STATUS_SUCCESS });

            WaitSemaphore?.ReleaseUpToMaximum(1);
        }

        private static NTSTATUS Reply(BinaryEmulator Instance, AlpcServerQueue Queue, uint Flags, uint MessageId, ReadOnlySpan<byte> Data)
        {
            if (!Queue.Delivered.Remove(MessageId, out AlpcMessage Request))
                return NTSTATUS.STATUS_INVALID_MESSAGE;

            if (IsDatagram(Request) && (Flags & ReleaseMessageFlag) != 0)
            {
                Request.Connection.DeliveredDatagrams--;
                ReleaseContext(Request);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Request.WaitsForReply)
            {
                Queue.Delivered.Add(MessageId, Request);
                return NTSTATUS.STATUS_INVALID_MESSAGE;
            }

            ReleaseContext(Request);

            // The end of the connection has already answered the client.
            if (!Request.Connection.AwaitingReply.Remove(Request))
                return NTSTATUS.STATUS_SUCCESS;

            AlpcWait Wait = Request.ReplyWait;
            if (Request.HostReply != null)
                RunHost(Request.HostReply, NTSTATUS.STATUS_SUCCESS, Data);
            else if (Wait.IsLive)
                Wait.Complete(Instance, WriteReply(Instance, Wait, LpcReply, 0, Request, Data, Instance.WinHelper.PID, CurrentThreadId(Instance)));

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CompleteConnect(BinaryEmulator Instance, AlpcWait Wait, AlpcMessage Request, ReadOnlySpan<byte> Data, ulong ProcessId, ulong ThreadId)
        {
            if (!TryWritePortHandle(Instance, Wait, out WinHandle Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Wait.MessagePtr != 0 ? WriteReply(Instance, Wait, LpcConnectionReply, 0, Request, Data, ProcessId, ThreadId) : NTSTATUS.STATUS_SUCCESS;
            if (Status != NTSTATUS.STATUS_SUCCESS)
                Instance.WinHelper.CloseHandle(Handle.Handle);
            return Status;
        }

        private static bool TryWritePortHandle(BinaryEmulator Instance, AlpcWait Wait, out WinHandle Handle)
        {
            Handle = Instance.WinHelper.OpenObjectHandle(Wait.Port, AccessMask.StandardRightsAll);
            if (Instance.WinHelper.WritePointer(Wait.PortHandlePtr, Handle.Handle))
                return true;

            Instance.WinHelper.CloseHandle(Handle.Handle);
            return false;
        }

        // NT returns from a connect without ALPC_MSGFLG_SYNC_REQUEST at once. The answer arrives when a thread waits where it
        // can see it, but not on a lock, or when the connecting thread yields, sleeps or ends.
        private static NTSTATUS CompleteAsyncConnect(BinaryEmulator Instance, AlpcWait Wait, AlpcMessage Request, byte[] Data, ulong ProcessId, ulong ThreadId)
        {
            if (!TryWritePortHandle(Instance, Wait, out _))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            AlpcConnection Connection = Request.Connection;
            Connection.PendingConnectReply = new AlpcMessage
            {
                Type = Data != null ? LpcConnectionReply : LpcCanceled,
                Data = Data ?? Array.Empty<byte>(),
                ProcessId = ProcessId,
                ThreadId = ThreadId,
                MessageId = Request.MessageId,
                CallbackId = Request.CallbackId,
                Sequence = ++Connection.NextClientSequence,
                Connection = Connection,
            };
            Connection.PendingReplyThread = (uint)Instance.CurrentThreadId;
            Instance.WinHelper.PendingConnectReplies.Add(Connection);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void DeliverConnectReplies(BinaryEmulator Instance, uint ThreadId)
        {
            List<AlpcConnection> Pending = Instance.WinHelper.PendingConnectReplies;
            for (int Index = 0; Index < Pending.Count;)
            {
                AlpcConnection Connection = Pending[Index];
                if (Connection.PendingReplyThread != ThreadId)
                {
                    Index++;
                    continue;
                }

                Pending.RemoveAt(Index);
                DeliverConnectReply(Instance, Connection);
            }
        }

        internal static void DeliverConnectRepliesTo(BinaryEmulator Instance, EmulatedThread Thread)
        {
            List<AlpcConnection> Pending = Instance.WinHelper.PendingConnectReplies;
            for (int Index = 0; Index < Pending.Count;)
            {
                AlpcConnection Connection = Pending[Index];
                if (!HasParkedListener(Instance, Connection.ClientPort, Thread))
                {
                    Index++;
                    continue;
                }

                Pending.RemoveAt(Index);
                DeliverConnectReply(Instance, Connection);
            }
        }

        internal static void DeliverConnectReplyForRoute(BinaryEmulator Instance, WinPort Port, WinIoCompletion Completion)
        {
            List<AlpcConnection> Pending = Instance.WinHelper.PendingConnectReplies;
            for (int Index = 0; Index < Pending.Count; Index++)
            {
                AlpcConnection Connection = Pending[Index];
                if (Connection.ClientPort != Port)
                    continue;

                if (Instance.HasParkedTaker(Completion))
                {
                    Pending.RemoveAt(Index);
                    DeliverConnectReply(Instance, Connection);
                }

                return;
            }
        }

        // This checks the same routes that Enqueue takes.
        private static bool HasParkedListener(BinaryEmulator Instance, WinPort Port, EmulatedThread Thread)
        {
            List<AlpcWait> Receivers = Port.Queue.Receivers;
            for (int i = 0; i < Receivers.Count; i++)
            {
                if (Receivers[i].IsLive)
                    return true;
            }

            List<ulong> Handles = Thread.WaitHandles;
            if (Handles != null)
            {
                for (int i = 0; i < Handles.Count; i++)
                {
                    if (Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(Handles[i]) == Port)
                        return true;
                }
            }

            WinIoCompletion Taken = Instance.CompletionTakenBy(Thread);
            return Taken != null && (Port.Queue.CompletionPort == Taken || Instance.HasWaitPacketOn(Port, Taken));
        }

        private static void DeliverConnectReply(BinaryEmulator Instance, AlpcConnection Connection)
        {
            AlpcMessage Reply = Connection.PendingConnectReply;
            Connection.PendingConnectReply = null;
            Enqueue(Instance, Connection.ClientPort, Reply);
        }

        private static void FlushConnectReply(BinaryEmulator Instance, AlpcConnection Connection)
        {
            if (Connection.PendingConnectReply == null)
                return;

            Instance.WinHelper.PendingConnectReplies.Remove(Connection);
            DeliverConnectReply(Instance, Connection);
        }

        private static void DropConnectReply(BinaryEmulator Instance, AlpcConnection Connection)
        {
            if (Connection.PendingConnectReply == null)
                return;

            Connection.PendingConnectReply = null;
            Instance.WinHelper.PendingConnectReplies.Remove(Connection);
        }

        // The reply and the connect answer write the length they produce.
        private static NTSTATUS WriteReply(BinaryEmulator Instance, AlpcWait Wait, ushort Type, ushort TypeFlags, AlpcMessage Request, ReadOnlySpan<byte> Data, ulong ProcessId, ulong ThreadId)
        {
            ulong Total = (ulong)(HeaderSize + Data.Length);
            if (Total > Wait.BufferLength)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            NTSTATUS Status = WriteMessage(Instance, Wait.MessagePtr, Type, TypeFlags, Data, ProcessId, ThreadId, Request.MessageId, Request.CallbackId);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Wait.BufferLengthPtr != 0 && !Instance.WinHelper.WriteUInt64(Wait.BufferLengthPtr, Total))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Wait.AttributesPtr != 0 && !Instance.WinHelper.WriteUInt32(Wait.AttributesPtr + 4, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a receive leaves the length alone unless the buffer is too small.
        private static NTSTATUS WriteReceived(BinaryEmulator Instance, AlpcReceiveQueue ReceiveQueue, AlpcMessage Message, ulong MessagePtr, ulong BufferLength, ulong BufferLengthPtr, ulong AttributesPtr)
        {
            ulong Total = (ulong)(HeaderSize + Message.Data.Length);
            if (Total > BufferLength)
                return Instance.WinHelper.WriteUInt64(BufferLengthPtr, Total) ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = WriteMessage(Instance, MessagePtr, Message.Type, Message.TypeFlags, Message.Data, Message.ProcessId, Message.ThreadId, Message.MessageId, Message.CallbackId);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            AlpcServerQueue Queue = ReceiveQueue as AlpcServerQueue;
            if (AttributesPtr != 0 && !WriteReceivedAttributes(Instance, Message, AttributesPtr, ToServer: Queue != null))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Queue != null && (Message.Type == LpcConnectionRequest || Message.Type == LpcRequest))
            {
                Queue.Delivered[Message.MessageId] = Message;
                Message.Data = Array.Empty<byte>();
                if (IsDatagram(Message))
                    Message.Connection.DeliveredDatagrams++;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a connection request carries only the token attribute. A client port has no port context.
        private static bool WriteReceivedAttributes(BinaryEmulator Instance, AlpcMessage Message, ulong AttributesPtr, bool ToServer)
        {
            if (!Instance.WinHelper.TryReadUInt32(AttributesPtr, out uint Allocated))
                return false;

            Span<byte> Buffer = stackalloc byte[0x20];
            uint Valid = 0;
            if ((Allocated & ContextAttribute) != 0 && Message.Type != LpcConnectionRequest)
            {
                Buffer.Clear();
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00), ToServer ? Message.Connection.PortContext : 0);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(ContextMessageOffset), Message.MessageContext);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10), Message.Sequence);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14), Message.MessageId);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18), Message.CallbackId);
                if (!Instance.WriteMemory(AttributesPtr + AttributeOffset(Allocated, ContextAttribute), Buffer))
                    return false;
                Valid |= ContextAttribute;
            }

            if ((Allocated & TokenAttribute) != 0 && ToServer)
            {
                Buffer.Clear();
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00), Message.Connection.TokenId);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08), Message.Connection.ClientAuthenticationId);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10), Message.Connection.Client.Token?.ModifiedId ?? 0);
                if (!Instance.WriteMemory(AttributesPtr + AttributeOffset(Allocated, TokenAttribute), Buffer.Slice(0, 0x18)))
                    return false;
                Valid |= TokenAttribute;
            }

            return Instance.WinHelper.WriteUInt32(AttributesPtr + 4, Valid);
        }

        private static NTSTATUS WriteMessage(BinaryEmulator Instance, ulong MessagePtr, ushort Type, ushort TypeFlags, ReadOnlySpan<byte> Data, ulong ProcessId, ulong ThreadId, uint MessageId, uint CallbackId)
        {
            Span<byte> Header = stackalloc byte[HeaderSize];
            Header.Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(OffDataLength), (ushort)Data.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(OffTotalLength), (ushort)(HeaderSize + Data.Length));
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(OffType), (ushort)(Type | TypeFlags));
            BinaryPrimitives.WriteUInt64LittleEndian(Header.Slice(OffProcessId), ProcessId);
            BinaryPrimitives.WriteUInt64LittleEndian(Header.Slice(OffThreadId), ThreadId);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(OffMessageId), MessageId);
            BinaryPrimitives.WriteUInt64LittleEndian(Header.Slice(OffCallbackId), CallbackId);

            if (!Instance.WriteMemory(MessagePtr, Header) || (Data.Length != 0 && !Instance.WriteMemory(MessagePtr + HeaderSize, Data)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS TryReadHeader(BinaryEmulator Instance, ulong MessagePtr, out uint MessageId, out ushort DataLength, out ushort TypeFlags)
        {
            MessageId = 0;
            DataLength = 0;
            TypeFlags = 0;

            Span<byte> Header = stackalloc byte[HeaderSize];
            if (!Instance.ReadMemory(MessagePtr, Header))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ushort Length = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(OffDataLength));
            ushort TotalLength = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(OffTotalLength));
            if (Length > MaxDataLength || TotalLength < HeaderSize + Length)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            MessageId = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(OffMessageId));
            DataLength = Length;
            TypeFlags = TypeFlagsOf(Header);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS TryReadMessage(BinaryEmulator Instance, ulong MessagePtr, out byte[] Data, out ushort TypeFlags)
        {
            Data = Array.Empty<byte>();
            NTSTATUS Status = TryReadHeader(Instance, MessagePtr, out _, out ushort DataLength, out TypeFlags);
            if (Status != NTSTATUS.STATUS_SUCCESS || DataLength == 0)
                return Status;

            Data = new byte[DataLength];
            return Instance.ReadMemory(MessagePtr + HeaderSize, Data) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        // Data points into the shared scratch buffer, so it is valid only until the syscall returns.
        private static NTSTATUS TryReadAnswer(BinaryEmulator Instance, ulong MessagePtr, out uint MessageId, out Span<byte> Data)
        {
            Data = Span<byte>.Empty;
            NTSTATUS Status = TryReadHeader(Instance, MessagePtr, out MessageId, out ushort DataLength, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS || DataLength == 0)
                return Status;

            Data = Instance.WinHelper.Shared.GetSpan(DataLength);
            return Instance.ReadMemory(MessagePtr + HeaderSize, Data) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        // The caller bumps WakeSignal once after all the waits it ends.
        private static bool FinishIfLive(AlpcWait Wait, NTSTATUS Status)
        {
            if (Wait == null || !Wait.IsLive)
                return false;

            Wait.Finish(Status);
            return true;
        }

        // A failure in Brovan's own client is not the guest server's, so its syscall still succeeds.
        private static void RunHost(HostReplyHandler Callback, NTSTATUS Status, ReadOnlySpan<byte> Data)
        {
            try
            {
                Callback(Status, Data);
            }
            catch (Exception Error)
            {
                LogHostFailure(Status, Error);
            }
        }

        private static void RunConnected(AlpcHost Host, NTSTATUS Status)
        {
            Action<NTSTATUS> Connected = Host.Connected;
            Host.Connected = null;
            try
            {
                Connected(Status);
            }
            catch (Exception Error)
            {
                LogHostFailure(Status, Error);
            }
        }

        private static void LogHostFailure(NTSTATUS Status, Exception Error)
        {
            Utils.LogError($"[-] ALPC: Brovan's client failed on an answer with status 0x{(uint)Status:X8}: {Error}");
        }

        private static void LogServerFailure(AlpcConnection Connection, Exception Error)
        {
            Utils.LogError($"[-] ALPC: Brovan's server of \"{Connection.ConnectionPort.Name}\" failed: {Error}");
        }

        private static ulong CurrentThreadId(BinaryEmulator Instance) => (ulong)(uint)Instance.CurrentThreadId;

        private static uint TakeId(ref uint Next)
        {
            if (++Next == 0)
                Next = 1;
            return Next;
        }
    }
}
