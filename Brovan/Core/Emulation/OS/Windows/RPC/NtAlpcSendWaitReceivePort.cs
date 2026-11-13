using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Core.Emulation.OS.Windows.AlpcMessaging;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtAlpcSendWaitReceivePort : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong PortHandle = Instance.WinHelper.GetArg(0);
            uint Flags = (uint)Instance.WinHelper.GetArg(1);
            ulong SendMessagePtr = Instance.WinHelper.GetArg(2);
            ulong SendMessageAttributesPtr = Instance.WinHelper.GetArg(3);
            ulong ReceiveMessagePtr = Instance.WinHelper.GetArg(4);
            ulong BufferLengthPtr = Instance.WinHelper.GetArg(5);
            ulong ReceiveMessageAttributesPtr = Instance.WinHelper.GetArg(6);
            ulong TimeoutPtr = Instance.WinHelper.GetArg(7);

            if (!Instance.WinHelper.HandleManager.TryGetHandle(PortHandle, out ulong PortKey, out HandleEntry PortEntry) || PortEntry.Object is not WinPort Port)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (AlpcMessaging.Owns(Port))
                return AlpcMessaging.SendWaitReceive(Instance, Port, Flags, SendMessagePtr, SendMessageAttributesPtr, ReceiveMessagePtr, BufferLengthPtr, ReceiveMessageAttributesPtr, TimeoutPtr);

            if (SendMessagePtr != 0 && Port.Handler != null && IsDisconnected(Port, PortKey))
                return NTSTATUS.STATUS_PORT_DISCONNECTED;

            if (SendMessagePtr == 0 && ReceiveMessagePtr != 0 && ServedQueueOf(Port, PortKey) is AlpcReceiveQueue Answers)
                return ReceiveFrom(Instance, Answers, null, ReceiveMessagePtr, BufferLengthPtr, ReceiveMessageAttributesPtr, TimeoutPtr);

            if (SendMessagePtr != 0 && !Instance.IsRegionMapped(SendMessagePtr, (ulong)HeaderSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReceiveMessagePtr != 0 && !Instance.IsRegionMapped(ReceiveMessagePtr, (ulong)HeaderSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong ReceiveBufferLength = 0;
            if (ReceiveMessagePtr != 0)
            {
                if (BufferLengthPtr != 0 && !Instance.IsRegionMapped(BufferLengthPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ReceiveBufferLength = BufferLengthPtr != 0 ? Instance._emulator.ReadMemoryULong(BufferLengthPtr) : 0;
                if (ReceiveBufferLength < (ulong)HeaderSize)
                {
                    if (BufferLengthPtr != 0)
                        Instance._emulator.WriteMemory(BufferLengthPtr, (ulong)HeaderSize);
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                }

                if (!Instance.IsRegionMapped(ReceiveMessagePtr, ReceiveBufferLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            byte[] SendBytes = null;
            ushort SendTotalLength = 0;

            if (SendMessagePtr != 0)
            {
                Span<byte> SendHeader = stackalloc byte[HeaderSize];
                if (!Instance.ReadMemory(SendMessagePtr, SendHeader))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                SendTotalLength = ReadU16(SendHeader, OffTotalLength);

                if (SendTotalLength < HeaderSize || SendTotalLength > 0xFFFF)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(SendMessagePtr, SendTotalLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                SendBytes = Instance.ReadMemory(SendMessagePtr, SendTotalLength);
            }

            // NT takes the sent attributes before it fills the received ones, which can be the same buffer.
            List<ulong> SentHandles = SendBytes != null ? ReadHandleAttribute(Instance, SendMessageAttributesPtr) : null;

            uint AllocatedAttributes = 0;
            if (ReceiveMessageAttributesPtr != 0)
            {
                NTSTATUS Probed = Instance.WinHelper.ProbeForWrite(ReceiveMessageAttributesPtr, AttributeHeaderSize);
                if (Probed != NTSTATUS.STATUS_SUCCESS)
                    return Probed;
                if (!Instance.WinHelper.TryReadUInt32(ReceiveMessageAttributesPtr, out AllocatedAttributes))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (SendBytes != null && (Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] ALPC send \"{Port.Name}\" len=0x{SendBytes.Length:X} reply={(ReceiveMessagePtr != 0 ? "yes" : "no")}", LogFlags.General);

            if (SendBytes == null && ReceiveMessagePtr != 0 && (Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] ALPC receive-only on \"{Port.Name}\"", LogFlags.General);

            if (ReceiveMessagePtr != 0)
                return SendAndReceive(Instance, Port, PortKey, PortHandle, Flags, SendBytes, SentHandles, ReceiveMessagePtr, ReceiveBufferLength, BufferLengthPtr,
                    ReceiveMessageAttributesPtr, AllocatedAttributes, TimeoutPtr);

            if (SendBytes != null)
            {
                ReadMessageIds(SendBytes, out uint SentMessageId, out _);
                if (SentMessageId != 0 && TryReleaseHandleBlob(Instance, Port, PortKey, SentMessageId))
                    return NTSTATUS.STATUS_SUCCESS;

                if (AlpcMessaging.Supported(Instance) && CsrssPortHandler.AnswersAsync(Port, SendBytes) && ServedQueueOf(Port, PortKey) is AlpcReceiveQueue Queued
                    && HasAnswerRoute(Queued, null))
                    return AnswerAfterSend(Instance, Port, PortKey, Queued, SendMessageAttributesPtr, SentHandles, SendBytes);

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtAlpcSendWaitReceivePort: Port=\"{Port.Name}\", Flags=0x{Flags:X}, SentLength=0x{SendBytes.Length:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (ReceiveMessagePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (TimeoutPtr != 0 && Instance.IsRegionMapped(TimeoutPtr, 8))
                return NTSTATUS.STATUS_TIMEOUT;

            return NTSTATUS.STATUS_TIMEOUT;
        }

        // A delay or host work runs the syscall again and reads the sent attributes again from what can be the same
        // buffer, so the receive attributes are written only after the handler answers.
        private static NTSTATUS SendAndReceive(BinaryEmulator Instance, WinPort Port, ulong PortKey, ulong PortHandle, uint Flags, byte[] SendBytes, List<ulong> SentHandles,
            ulong ReceiveMessagePtr, ulong ReceiveBufferLength, ulong BufferLengthPtr, ulong ReceiveAttributesPtr, uint AllocatedAttributes, ulong TimeoutPtr)
        {
            PortReply Reply = null;
            try
            {
                if (SendBytes != null && Port.Handler != null)
                {
                    Reply = new PortReply { Port = Port, HandleKey = PortKey, SenderWaits = true, SentHandles = SentHandles };
                    RunHandler(Instance, Reply, SendBytes);

                    if (Reply.Deferred == null)
                    {
                        long Delay = Reply.NotBeforeTick - Instance.EmulatedTickCount64;
                        if (Delay > 0 && Instance.WinHelper.TryContinuePipeWait(PortHandle, (int)Delay, (int)Delay))
                            return NTSTATUS.STATUS_PENDING;

                        if (Reply.HostWork != null && Instance.WinHelper.TryRetrySyscallWhenDone(Reply.HostWork))
                            return NTSTATUS.STATUS_PENDING;
                    }
                }

                if (ReceiveAttributesPtr != 0 && !Instance.WinHelper.WriteUInt32(ReceiveAttributesPtr + 4, 0))
                {
                    if (Reply?.Deferred != null)
                        AbandonDeferredAnswer(Instance, Reply.Deferred, WakeSender: false);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (Reply?.Deferred != null)
                    return ParkForDeferredAnswer(Instance, Port, Reply, ReceiveMessagePtr, ReceiveBufferLength, BufferLengthPtr, ReceiveAttributesPtr, TimeoutPtr);

                Span<byte> Whole = Reply != null ? Reply.Data : stackalloc byte[HeaderSize];
                NTSTATUS Written = WriteHandlerReply(Instance, Whole, ReceiveMessagePtr, ReceiveBufferLength, BufferLengthPtr);
                if (Reply != null)
                    DeliverReplyHandles(Instance, Reply, Whole, Written == NTSTATUS.STATUS_SUCCESS, ReceiveAttributesPtr, AllocatedAttributes);
                if (Written == NTSTATUS.STATUS_SUCCESS && (Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtAlpcSendWaitReceivePort: Port=\"{Port.Name}\", Flags=0x{Flags:X}, ReplyLength=0x{Whole.Length:X}", LogFlags.Syscall);

                return Written;
            }
            finally
            {
                CloseAttachedHandles(Instance, Reply);
            }
        }

        private static NTSTATUS AnswerAfterSend(BinaryEmulator Instance, WinPort Port, ulong PortKey, AlpcReceiveQueue Answers, ulong SendAttributesPtr, List<ulong> SentHandles, byte[] SendBytes)
        {
            if (IsFull(Answers))
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            ulong AttributeHeader = 0;
            if (SendAttributesPtr != 0 && !Instance.WinHelper.TryReadUInt64(SendAttributesPtr, out AttributeHeader))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS ContextStatus = ReadMessageContext(Instance, SendAttributesPtr, AttributeHeader, out ulong MessageContext);
            if (ContextStatus != NTSTATUS.STATUS_SUCCESS)
                return ContextStatus;

            AlpcRequestFacts Facts = new AlpcRequestFacts(TypeFlagsOf(SendBytes), NewCallbackId(), MessageContext);
            PortReply Reply = new PortReply { Port = Port, HandleKey = PortKey, SenderWaits = false, Facts = Facts, SentHandles = SentHandles };
            try
            {
                RunHandler(Instance, Reply, SendBytes);
                if (CarriesSyscallWork(Reply))
                    return RefuseDeferral(Instance, Port, Reply);

                if (Reply.Deferred != null)
                    return NTSTATUS.STATUS_SUCCESS;

                return QueueHandlerReply(Instance, Port, PortKey, Answers, Facts, Reply.Data);
            }
            finally
            {
                CloseAttachedHandles(Instance, Reply);
            }
        }

        private static NTSTATUS ParkForDeferredAnswer(BinaryEmulator Instance, WinPort Port, PortReply Reply, ulong ReceiveMessagePtr, ulong ReceiveBufferLength,
            ulong BufferLengthPtr, ulong ReceiveAttributesPtr, ulong TimeoutPtr)
        {
            if (CarriesSyscallWork(Reply))
                return RefuseDeferral(Instance, Port, Reply);

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
            {
                AbandonDeferredAnswer(Instance, Reply.Deferred, WakeSender: false);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            AlpcWait Wait = new AlpcWait
            {
                Kind = AlpcWaitKind.Reply,
                Port = Port,
                MessagePtr = ReceiveMessagePtr,
                BufferLength = ReceiveBufferLength,
                BufferLengthPtr = BufferLengthPtr,
                AttributesPtr = ReceiveAttributesPtr,
            };

            Reply.Deferred.Wait = Wait;
            Instance.WinHelper.ParkForIoRequest(Wait, Instance.WinHelper.ParseRelativeDeadlineMs(Timeout));
            return NTSTATUS.STATUS_PENDING;
        }

        // A delay, host work and handles reach the sender only through the syscall that sent.
        private static bool CarriesSyscallWork(PortReply Reply) => Reply.HostWork != null || Reply.NotBeforeTick != 0 || Reply.Handles != null;

        private static NTSTATUS RefuseDeferral(BinaryEmulator Instance, WinPort Port, PortReply Reply)
        {
            if (Reply.Deferred != null)
                AbandonDeferredAnswer(Instance, Reply.Deferred, WakeSender: false);

            Utils.LogError($"[-] ALPC: the handler of \"{Port.Name}\" defers or carries handles in an answer that it cannot give now.");
            return NTSTATUS.STATUS_NOT_SUPPORTED;
        }

        // The caller makes the reply, so it can close what a handler that throws has attached.
        private static void RunHandler(BinaryEmulator Instance, PortReply Reply, byte[] SendBytes)
        {
            Reply.Port.Handler(Reply.Port, SendBytes, Reply, Instance);
            Reply.Data ??= SendBytes;
        }

        internal static NTSTATUS WriteHandlerReply(BinaryEmulator Instance, Span<byte> Reply, ulong MessagePtr, ulong BufferLength, ulong BufferLengthPtr)
        {
            ulong WriteLength = (ulong)Reply.Length;
            if (WriteLength > BufferLength)
            {
                if (BufferLengthPtr != 0)
                    Instance._emulator.WriteMemory(BufferLengthPtr, WriteLength);
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            FinalizeReplyHeader(Reply, (ushort)WriteLength);
            if (!Instance._emulator.WriteMemory(MessagePtr, Reply))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (BufferLengthPtr != 0)
                Instance._emulator.WriteMemory(BufferLengthPtr, WriteLength);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT finds an attribute by the attributes the buffer allocates, not the valid ones (AlpcGetMessageAttribute).
        private static List<ulong> ReadHandleAttribute(BinaryEmulator Instance, ulong AttributesPtr)
        {
            Span<byte> Header = stackalloc byte[AttributeHeaderSize];
            if (AttributesPtr == 0 || !Instance.ReadMemory(AttributesPtr, Header))
                return null;

            uint AllocatedAttributes = ReadU32(Header, 0);
            uint ValidAttributes = ReadU32(Header, 4);
            if ((ValidAttributes & AllocatedAttributes & HandleAttribute) == 0)
                return null;

            if (!Supported(Instance))
            {
                ReportDroppedThirtyTwoBitHandles();
                return null;
            }

            Span<byte> Attribute = stackalloc byte[HandleAttributeSize];
            if (!Instance.ReadMemory(AttributesPtr + AttributeOffset(AllocatedAttributes, HandleAttribute), Attribute))
                return null;

            if ((ReadU32(Attribute, 0) & IndirectHandleFlag) != 0)
            {
                Utils.LogError("[-] ALPC: a request sends several handles; handler ports take one, so it goes without them.");
                return null;
            }

            ulong Handle = BinaryPrimitives.ReadUInt64LittleEndian(Attribute.Slice(0x08));
            if (Handle == 0)
                return null;

            return new List<ulong> { Handle };
        }

        private static void FinalizeReplyHeader(Span<byte> Reply, ushort TotalLength)
        {
            if (Reply.Length < HeaderSize)
                return;

            WriteU16(Reply, OffTotalLength, TotalLength);
            WriteU16(Reply, OffDataLength, TotalLength >= HeaderSize ? (ushort)(TotalLength - HeaderSize) : (ushort)0);

            if (ReadU32(Reply, OffMessageId) == 0)
                WriteU32(Reply, OffMessageId, NewMessageId());
        }

        private static ushort ReadU16(ReadOnlySpan<byte> Buffer, int Offset)
        {
            if (Offset < 0 || Offset > Buffer.Length - 2)
                return 0;

            return (ushort)(Buffer[Offset] | (Buffer[Offset + 1] << 8));
        }

        private static uint ReadU32(ReadOnlySpan<byte> Buffer, int Offset)
        {
            if (Offset < 0 || Offset > Buffer.Length - 4)
                return 0;

            return (uint)(Buffer[Offset] | (Buffer[Offset + 1] << 8) | (Buffer[Offset + 2] << 16) | (Buffer[Offset + 3] << 24));
        }

        private static void WriteU16(Span<byte> Buffer, int Offset, ushort Value)
        {
            if (Offset < 0 || Offset > Buffer.Length - 2)
                return;

            Buffer[Offset] = (byte)Value;
            Buffer[Offset + 1] = (byte)(Value >> 8);
        }

        private static void WriteU32(Span<byte> Buffer, int Offset, uint Value)
        {
            if (Offset < 0 || Offset > Buffer.Length - 4)
                return;

            Buffer[Offset] = (byte)Value;
            Buffer[Offset + 1] = (byte)(Value >> 8);
            Buffer[Offset + 2] = (byte)(Value >> 16);
            Buffer[Offset + 3] = (byte)(Value >> 24);
        }
    }
}