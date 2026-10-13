using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class AlpcServerQueue
    {
        internal readonly Queue<AlpcMessage> Pending = new Queue<AlpcMessage>();
        internal readonly List<AlpcWait> Receivers = new List<AlpcWait>();
        // Received, but not yet accepted or replied to.
        internal readonly Dictionary<uint, AlpcMessage> Delivered = new Dictionary<uint, AlpcMessage>();
        internal readonly HashSet<AlpcConnection> Connections = new HashSet<AlpcConnection>();
        internal WinIoCompletion CompletionPort;
        internal ulong CompletionKey;
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
        internal AlpcConnectionState State;
        internal ulong PortContext;
        internal ulong TokenId;
        internal uint ClosedCallbackId;
        internal uint NextSequence;
        internal AlpcWait ConnectWait;
        internal readonly List<AlpcMessage> AwaitingReply = new List<AlpcMessage>();
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
        internal AlpcConnection Connection;
        internal AlpcWait ReplyWait;

        internal bool WaitsForReply => ReplyWait != null;
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
        internal EmulatedThread Thread;
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

        internal bool IsLive => !Completed && Thread.State != EmulatedThreadState.Terminated && WinEmulatedThread.TryGetState(Thread)?.IoRequest == this;
    }

    // ALPC between guest ports of this process, with x64 layouts.
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
        private const int MaxDataLength = 0xFFFF - HeaderSize;

        private const ushort LpcRequest = 1;
        private const ushort LpcReply = 2;
        private const ushort LpcPortClosed = 5;
        private const ushort LpcConnectionRequest = 10;
        private const ushort LpcConnectionReply = 11;
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
        private static readonly (uint Flag, int Size)[] AttributeSizes =
        {
            (SecurityAttribute, 0x18), (ViewAttribute, 0x20), (ContextAttribute, 0x20), (HandleAttribute, HandleAttributeSize),
            (TokenAttribute, 0x18), (DirectAttribute, 0x08), (WorkOnBehalfAttribute, 0x08),
        };

        private const int MaxPendingMessages = 0x4000;
        private const int MaxReceivers = 0x400;

        private static uint NextMessageId;
        private static uint NextCallbackId;

        internal static bool Supported(BinaryEmulator Instance) => Instance.WinHelper.PointerSize == 8;

        internal static bool Owns(WinPort Port) => Port.Queue != null || Port.Connection != null;

        internal static NTSTATUS SendWaitReceive(BinaryEmulator Instance, WinPort Port, ulong SendMessagePtr, ulong SendAttributesPtr, ulong ReceiveMessagePtr, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            if (!Supported(Instance))
                return Unsupported(Port);

            return Port.IsClientEnd
                ? SendGuest(Instance, Port, SendMessagePtr, SendAttributesPtr, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr)
                : ServerSendWaitReceive(Instance, Port, SendMessagePtr, ReceiveMessagePtr, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr);
        }

        // NT: NtWaitForWorkViaWorkerFactory sends the message a thread pool callback left, and ignores the result.
        internal static void SendDeferred(BinaryEmulator Instance, ulong PortHandle, ulong MessagePtr)
        {
            WinPort Port = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle);
            if (Port == null)
                return;

            if (!Owns(Port))
            {
                Utils.LogError($"[-] ALPC: a thread pool callback leaves a message for \"{Port.Name}\", a port Brovan serves.");
                return;
            }

            SendWaitReceive(Instance, Port, MessagePtr, 0, 0, 0, 0, 0);
        }

        internal static WinPort CreateConnectionPort(string Name)
        {
            return new WinPort { Name = Name, Queue = new AlpcServerQueue() };
        }

        internal static NTSTATUS AssociateCompletionPort(BinaryEmulator Instance, WinPort Port, ulong CompletionKey, ulong CompletionHandle)
        {
            WinIoCompletion Completion = Instance.WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(CompletionHandle);
            if (Completion == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Port.Queue.CompletionPort = Completion;
            Port.Queue.CompletionKey = CompletionKey;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS ConnectGuest(BinaryEmulator Instance, WinPort ConnectionPort, ulong PortHandlePtr, ulong MessagePtr, ulong BufferLengthPtr, ulong TimeoutPtr)
        {
            if (!Supported(Instance))
                return Unsupported(ConnectionPort);

            ulong BufferLength = 0;
            if (BufferLengthPtr != 0 && !Instance.WinHelper.TryReadUInt64(BufferLengthPtr, out BufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            byte[] Data = Array.Empty<byte>();
            if (MessagePtr != 0)
            {
                NTSTATUS ReadStatus = TryReadMessage(Instance, MessagePtr, out Data);
                if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                    return ReadStatus;
            }

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            AlpcServerQueue Queue = ConnectionPort.Queue;
            if (Queue.Pending.Count >= MaxPendingMessages)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            AlpcConnection Connection = NewConnection(ConnectionPort);
            AlpcWait Wait = new AlpcWait
            {
                Kind = AlpcWaitKind.Connect,
                Thread = Instance.CurrentThread,
                Port = new WinPort { Connection = Connection, IsClientEnd = true },
                PortHandlePtr = PortHandlePtr,
                MessagePtr = MessagePtr,
                BufferLength = BufferLength,
                BufferLengthPtr = BufferLengthPtr,
            };

            Connection.ConnectWait = Wait;
            Enqueue(Instance, Queue, NewMessage(Instance, Connection, LpcConnectionRequest, Data));
            Instance.WinHelper.ParkForIoRequest(Wait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
            return NTSTATUS.STATUS_PENDING;
        }

        internal static NTSTATUS Accept(BinaryEmulator Instance, WinPort ConnectionPort, ulong PortHandlePtr, ulong PortContext, ulong MessagePtr, bool AcceptConnection)
        {
            if (!Supported(Instance))
                return Unsupported(ConnectionPort);

            if (MessagePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS ReadStatus = TryReadAnswer(Instance, MessagePtr, out uint MessageId, out Span<byte> Data);
            if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                return ReadStatus;

            AlpcServerQueue Queue = ConnectionPort.Queue;
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
            if (Wait == null || !Wait.IsLive)
            {
                Queue.Delivered.Remove(MessageId);
                EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
                return NTSTATUS.STATUS_PORT_DISCONNECTED;
            }

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(new WinPort { Connection = Connection }, AccessMask.StandardRightsAll);
            if (!Instance.WinHelper.WritePointer(PortHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Queue.Delivered.Remove(MessageId);
            Connection.PortContext = PortContext;
            Connection.State = AlpcConnectionState.Connected;
            Connection.ConnectWait = null;
            Complete(Instance, Wait, CompleteConnect(Instance, Wait, Request, Data));
            return NTSTATUS.STATUS_SUCCESS;
        }

        // Runs when the last handle to the port closes.
        internal static void PortClosed(BinaryEmulator Instance, WinPort Port)
        {
            AlpcConnection Connection = Port.Connection;
            if (Connection != null)
            {
                bool NotifyServer = Port.IsClientEnd && Connection.State == AlpcConnectionState.Connected;
                EndConnection(Instance, Connection, NTSTATUS.STATUS_PORT_DISCONNECTED);
                if (NotifyServer)
                {
                    Enqueue(Instance, Connection.ConnectionPort.Queue, new AlpcMessage
                    {
                        Type = LpcPortClosed,
                        Data = PortClosedData,
                        MessageId = TakeId(ref NextMessageId),
                        CallbackId = Connection.ClosedCallbackId,
                        Sequence = ++Connection.NextSequence,
                        Connection = Connection,
                    });
                }

                return;
            }

            AlpcServerQueue Queue = Port.Queue;
            if (Queue == null)
                return;

            bool Woke = false;
            foreach (AlpcConnection Open in Queue.Connections)
                Woke |= EndWaits(Open, NTSTATUS.STATUS_PORT_DISCONNECTED);

            foreach (AlpcWait Receiver in Queue.Receivers)
                Woke |= FinishIfLive(Receiver, NTSTATUS.STATUS_PORT_DISCONNECTED);

            Queue.Connections.Clear();
            Queue.Receivers.Clear();
            Queue.Pending.Clear();
            Queue.Delivered.Clear();
            Queue.CompletionPort = null;
            if (Woke)
                Instance.WakeSignal.Bump();
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
            {
                Utils.LogError($"[-] ALPC: a client of \"{Connection.ConnectionPort.Name}\" waits for messages from its server, which ports of this process do not send.");
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            if (Connection.State != AlpcConnectionState.Connected)
                return NTSTATUS.STATUS_PORT_DISCONNECTED;

            if (SendAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadUInt32(SendAttributesPtr + 4, out uint SendValid))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if ((SendValid & CarriedAttributes) != 0)
                {
                    Utils.LogError($"[-] ALPC: a client of \"{Connection.ConnectionPort.Name}\" sends attributes 0x{SendValid:X8}; views and handles do not travel between ports of this process.");
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                }
            }

            NTSTATUS ReadStatus = TryReadMessage(Instance, SendMessagePtr, out byte[] Data);
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

            AlpcServerQueue Queue = Connection.ConnectionPort.Queue;
            if (Queue.Pending.Count >= MaxPendingMessages)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            AlpcMessage Message = NewMessage(Instance, Connection, LpcRequest, Data);
            Message.Sequence = ++Connection.NextSequence;
            if (WaitsForReply)
            {
                Message.ReplyWait = new AlpcWait
                {
                    Kind = AlpcWaitKind.Reply,
                    Thread = Instance.CurrentThread,
                    MessagePtr = ReceiveMessagePtr,
                    BufferLength = BufferLength,
                    BufferLengthPtr = BufferLengthPtr,
                    AttributesPtr = ReceiveAttributesPtr,
                };

                Connection.AwaitingReply.Add(Message);
            }

            Enqueue(Instance, Queue, Message);
            if (!WaitsForReply)
                return NTSTATUS.STATUS_SUCCESS;

            Instance.WinHelper.ParkForIoRequest(Message.ReplyWait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
            return NTSTATUS.STATUS_PENDING;
        }

        // NT: a send on a connection port replies to the request with the same message id.
        private static NTSTATUS ServerSendWaitReceive(BinaryEmulator Instance, WinPort Port, ulong SendMessagePtr, ulong ReceiveMessagePtr, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            AlpcServerQueue Queue = Port.Queue ?? Port.Connection.ConnectionPort.Queue;
            if (SendMessagePtr != 0)
            {
                NTSTATUS ReplyStatus = Reply(Instance, Queue, SendMessagePtr);
                if (ReplyStatus != NTSTATUS.STATUS_SUCCESS)
                    return ReplyStatus;
            }

            if (ReceiveMessagePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (Port.Queue == null)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

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

            // NT: a port with a completion port never waits in a receive.
            if (Queue.CompletionPort != null)
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
                Thread = Instance.CurrentThread,
                MessagePtr = ReceiveMessagePtr,
                BufferLength = BufferLength,
                BufferLengthPtr = BufferLengthPtr,
                AttributesPtr = ReceiveAttributesPtr,
            };

            Queue.Receivers.Add(Wait);
            Instance.WinHelper.ParkForIoRequest(Wait, Deadline);
            return NTSTATUS.STATUS_PENDING;
        }

        private static AlpcConnection NewConnection(WinPort ConnectionPort)
        {
            AlpcConnection Connection = new AlpcConnection
            {
                ConnectionPort = ConnectionPort,
                State = AlpcConnectionState.Connecting,
                TokenId = NtAllocateLocallyUniqueId.Allocate(),
                ClosedCallbackId = TakeId(ref NextCallbackId),
            };

            ConnectionPort.Queue.Connections.Add(Connection);
            return Connection;
        }

        private static AlpcMessage NewMessage(BinaryEmulator Instance, AlpcConnection Connection, ushort Type, byte[] Data)
        {
            return new AlpcMessage
            {
                Type = Type,
                TypeFlags = LpcContinuationRequired,
                Data = Data,
                ProcessId = Instance.WinHelper.PID,
                ThreadId = CurrentThreadId(Instance),
                MessageId = TakeId(ref NextMessageId),
                CallbackId = TakeId(ref NextCallbackId),
                Connection = Connection,
            };
        }

        private static void EndConnection(BinaryEmulator Instance, AlpcConnection Connection, NTSTATUS Status)
        {
            if (Connection.State == AlpcConnectionState.Closed)
                return;

            Connection.ConnectionPort.Queue.Connections.Remove(Connection);
            if (EndWaits(Connection, Status))
                Instance.WakeSignal.Bump();
        }

        private static bool EndWaits(AlpcConnection Connection, NTSTATUS Status)
        {
            Connection.State = AlpcConnectionState.Closed;
            bool Woke = FinishIfLive(Connection.ConnectWait, Status);
            Connection.ConnectWait = null;

            foreach (AlpcMessage Waiting in Connection.AwaitingReply)
                Woke |= FinishIfLive(Waiting.ReplyWait, NTSTATUS.STATUS_PORT_DISCONNECTED);

            Connection.AwaitingReply.Clear();
            return Woke;
        }

        private static void Enqueue(BinaryEmulator Instance, AlpcServerQueue Queue, AlpcMessage Message)
        {
            while (Queue.Receivers.Count > 0)
            {
                AlpcWait Receiver = Queue.Receivers[0];
                Queue.Receivers.RemoveAt(0);
                if (!Receiver.IsLive)
                    continue;

                NTSTATUS Status = WriteReceived(Instance, Queue, Message, Receiver.MessagePtr, Receiver.BufferLength, Receiver.BufferLengthPtr, Receiver.AttributesPtr);
                Complete(Instance, Receiver, Status);
                if (Status == NTSTATUS.STATUS_SUCCESS)
                    return;
            }

            Queue.Pending.Enqueue(Message);
            Queue.CompletionPort?.Post(new WinIoCompletionEntry { KeyContext = Queue.CompletionKey, IoStatus = NTSTATUS.STATUS_SUCCESS });
        }

        private static NTSTATUS Reply(BinaryEmulator Instance, AlpcServerQueue Queue, ulong MessagePtr)
        {
            NTSTATUS ReadStatus = TryReadAnswer(Instance, MessagePtr, out uint MessageId, out Span<byte> Data);
            if (ReadStatus != NTSTATUS.STATUS_SUCCESS)
                return ReadStatus;

            if (!Queue.Delivered.Remove(MessageId, out AlpcMessage Request))
                return NTSTATUS.STATUS_INVALID_MESSAGE;

            if (!Request.WaitsForReply)
            {
                Queue.Delivered.Add(MessageId, Request);
                return NTSTATUS.STATUS_INVALID_MESSAGE;
            }

            Request.Connection.AwaitingReply.Remove(Request);
            AlpcWait Wait = Request.ReplyWait;
            if (Wait.IsLive)
                Complete(Instance, Wait, WriteReply(Instance, Wait, LpcReply, Request, Data));

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CompleteConnect(BinaryEmulator Instance, AlpcWait Wait, AlpcMessage Request, ReadOnlySpan<byte> Data)
        {
            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Wait.Port, AccessMask.StandardRightsAll);
            if (!Instance.WinHelper.WritePointer(Wait.PortHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Wait.MessagePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            return WriteReply(Instance, Wait, LpcConnectionReply, Request, Data);
        }

        // The reply and the connect answer write the length they produce.
        private static NTSTATUS WriteReply(BinaryEmulator Instance, AlpcWait Wait, ushort Type, AlpcMessage Request, ReadOnlySpan<byte> Data)
        {
            ulong Total = (ulong)(HeaderSize + Data.Length);
            if (Total > Wait.BufferLength)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            NTSTATUS Status = WriteMessage(Instance, Wait.MessagePtr, Type, 0, Data, Instance.WinHelper.PID, CurrentThreadId(Instance), Request.MessageId, Request.CallbackId);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Wait.BufferLengthPtr != 0 && !Instance.WinHelper.WriteUInt64(Wait.BufferLengthPtr, Total))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Wait.AttributesPtr != 0 && !Instance.WinHelper.WriteUInt32(Wait.AttributesPtr + 4, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a receive leaves the length alone unless the buffer is too small.
        private static NTSTATUS WriteReceived(BinaryEmulator Instance, AlpcServerQueue Queue, AlpcMessage Message, ulong MessagePtr, ulong BufferLength, ulong BufferLengthPtr, ulong AttributesPtr)
        {
            ulong Total = (ulong)(HeaderSize + Message.Data.Length);
            if (Total > BufferLength)
                return Instance.WinHelper.WriteUInt64(BufferLengthPtr, Total) ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = WriteMessage(Instance, MessagePtr, Message.Type, Message.TypeFlags, Message.Data, Message.ProcessId, Message.ThreadId, Message.MessageId, Message.CallbackId);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (AttributesPtr != 0 && !WriteReceivedAttributes(Instance, Message, AttributesPtr))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Message.Type == LpcConnectionRequest || Message.WaitsForReply)
            {
                Queue.Delivered[Message.MessageId] = Message;
                Message.Data = Array.Empty<byte>();
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a connection request carries only the token attribute.
        private static bool WriteReceivedAttributes(BinaryEmulator Instance, AlpcMessage Message, ulong AttributesPtr)
        {
            if (!Instance.WinHelper.TryReadUInt32(AttributesPtr, out uint Allocated))
                return false;

            Span<byte> Buffer = stackalloc byte[0x20];
            uint Valid = 0;
            if ((Allocated & ContextAttribute) != 0 && Message.Type != LpcConnectionRequest)
            {
                Buffer.Clear();
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00), Message.Connection.PortContext);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10), Message.Sequence);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14), Message.MessageId);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18), Message.CallbackId);
                if (!Instance.WriteMemory(AttributesPtr + AttributeOffset(Allocated, ContextAttribute), Buffer))
                    return false;
                Valid |= ContextAttribute;
            }

            if ((Allocated & TokenAttribute) != 0)
            {
                WinProcess Process = Instance.WinHelper.OwnProcess;
                Buffer.Clear();
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00), Message.Connection.TokenId);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08), NtQueryInformationToken.AuthenticationIdOf(Process?.RunningUser ?? Instance.WinHelper.CurrentUser));
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10), Process?.GetPrimaryToken().ModifiedId ?? 0);
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

        private static NTSTATUS TryReadHeader(BinaryEmulator Instance, ulong MessagePtr, out uint MessageId, out ushort DataLength)
        {
            MessageId = 0;
            DataLength = 0;

            Span<byte> Header = stackalloc byte[HeaderSize];
            if (!Instance.ReadMemory(MessagePtr, Header))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ushort Length = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(OffDataLength));
            ushort TotalLength = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(OffTotalLength));
            if (Length > MaxDataLength || TotalLength < HeaderSize + Length)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            MessageId = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(OffMessageId));
            DataLength = Length;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS TryReadMessage(BinaryEmulator Instance, ulong MessagePtr, out byte[] Data)
        {
            Data = Array.Empty<byte>();
            NTSTATUS Status = TryReadHeader(Instance, MessagePtr, out _, out ushort DataLength);
            if (Status != NTSTATUS.STATUS_SUCCESS || DataLength == 0)
                return Status;

            Data = new byte[DataLength];
            return Instance.ReadMemory(MessagePtr + HeaderSize, Data) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        // Data points into the shared scratch buffer, so it is valid only until the syscall returns.
        private static NTSTATUS TryReadAnswer(BinaryEmulator Instance, ulong MessagePtr, out uint MessageId, out Span<byte> Data)
        {
            Data = Span<byte>.Empty;
            NTSTATUS Status = TryReadHeader(Instance, MessagePtr, out MessageId, out ushort DataLength);
            if (Status != NTSTATUS.STATUS_SUCCESS || DataLength == 0)
                return Status;

            Data = Instance.WinHelper.Shared.GetSpan(DataLength);
            return Instance.ReadMemory(MessagePtr + HeaderSize, Data) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static void Complete(BinaryEmulator Instance, AlpcWait Wait, NTSTATUS Status)
        {
            Finish(Wait, Status);
            Instance.WakeSignal.Bump();
        }

        // The caller bumps WakeSignal once after all the waits it ends.
        private static bool FinishIfLive(AlpcWait Wait, NTSTATUS Status)
        {
            if (Wait == null || !Wait.IsLive)
                return false;

            Finish(Wait, Status);
            return true;
        }

        private static void Finish(AlpcWait Wait, NTSTATUS Status)
        {
            Wait.Status = Status;
            Wait.Completed = true;
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
