using System;
using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Core.Emulation.OS.Windows.AlpcMessaging;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtAlpcSendWaitReceivePort : IWinSyscall
    {
        private static readonly object SyncRoot = new object();
        private static uint NextMessageId = 1;

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

            uint AllocatedAttributes = 0;
            if (ReceiveMessageAttributesPtr != 0 && Instance.IsRegionMapped(ReceiveMessageAttributesPtr, 8))
            {
                AllocatedAttributes = Instance._emulator.ReadMemoryUInt(ReceiveMessageAttributesPtr);
                Instance._emulator.WriteMemory(ReceiveMessageAttributesPtr + 0, AllocatedAttributes);
                Instance._emulator.WriteMemory(ReceiveMessageAttributesPtr + 4, 0u);
            }

            if (SendBytes != null && (Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] ALPC send \"{Port.Name}\" len=0x{SendBytes.Length:X} reply={(ReceiveMessagePtr != 0 ? "yes" : "no")}", LogFlags.General);

            if (SendBytes == null && ReceiveMessagePtr != 0 && (Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[+] ALPC receive-only on \"{Port.Name}\"", LogFlags.General);

            if (ReceiveMessagePtr != 0)
            {
                byte[] ReplyBytes = null;
                PortReply Reply = null;
                if (SendBytes != null && Port.Handler != null)
                {
                    Reply = new PortReply { Port = Port, HandleKey = PortKey };
                    Port.ReceivedHandles = ReadHandleAttribute(Instance, SendMessageAttributesPtr);
                    Port.Handler(Port, SendBytes, Reply, Instance);
                    ReplyBytes = Reply.Data ?? SendBytes;

                    long Delay = Reply.NotBeforeTick - Instance.EmulatedTickCount64;
                    if (Delay > 0 && Instance.WinHelper.TryContinuePipeWait(PortHandle, (int)Delay, (int)Delay))
                        return NTSTATUS.STATUS_PENDING;

                    if (Reply.HostWork != null && Instance.WinHelper.TryRetrySyscallWhenDone(Reply.HostWork))
                        return NTSTATUS.STATUS_PENDING;
                }

                Port.DeliveredHandles = Reply?.Handles;
                if (Port.DeliveredHandles != null)
                    PublishHandleAttribute(Instance, ReceiveMessageAttributesPtr, AllocatedAttributes, Port.DeliveredHandles.Count);

                ulong WriteLength = (ulong)(ReplyBytes?.Length ?? HeaderSize);
                if (WriteLength > ReceiveBufferLength)
                {
                    if (BufferLengthPtr != 0)
                        Instance._emulator.WriteMemory(BufferLengthPtr, WriteLength);
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                }

                if (ReplyBytes != null)
                {
                    FinalizeReplyHeader(ReplyBytes, (ushort)WriteLength);
                    if (!Instance._emulator.WriteMemory(ReceiveMessagePtr, ReplyBytes))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
                else
                {
                    Span<byte> EmptyReply = stackalloc byte[HeaderSize];
                    FinalizeReplyHeader(EmptyReply, HeaderSize);
                    if (!Instance._emulator.WriteMemory(ReceiveMessagePtr, EmptyReply))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (BufferLengthPtr != 0)
                    Instance._emulator.WriteMemory(BufferLengthPtr, WriteLength);

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtAlpcSendWaitReceivePort: Port=\"{Port.Name}\", Flags=0x{Flags:X}, ReplyLength=0x{WriteLength:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (SendBytes != null)
            {
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

        /// <summary>
        /// Announces handles that travel with the reply.
        /// </summary>
        private static void PublishHandleAttribute(BinaryEmulator Instance, ulong AttributesPtr, uint AllocatedAttributes, int HandleCount)
        {
            if (AttributesPtr == 0 || HandleCount <= 0 || (AllocatedAttributes & HandleAttribute) == 0)
                return;

            ulong Offset = AttributeOffset(AllocatedAttributes, HandleAttribute);
            if (!Instance.IsRegionMapped(AttributesPtr + Offset, HandleAttributeSize))
                return;

            Instance._emulator.WriteMemory(AttributesPtr + 4, HandleAttribute);
            Instance._emulator.WriteMemory(AttributesPtr + Offset + 0x00, 0u);
            Instance._emulator.WriteMemory(AttributesPtr + Offset + 0x08, 0UL, 8);
            Instance._emulator.WriteMemory(AttributesPtr + Offset + 0x10, (uint)HandleCount);
        }

        private static List<ulong> ReadHandleAttribute(BinaryEmulator Instance, ulong AttributesPtr)
        {
            if (AttributesPtr == 0 || !Instance.IsRegionMapped(AttributesPtr, AttributeHeaderSize))
                return null;

            uint ValidAttributes = Instance._emulator.ReadMemoryUInt(AttributesPtr + 4);
            if ((ValidAttributes & HandleAttribute) == 0)
                return null;

            ulong Offset = AttributeOffset(ValidAttributes, HandleAttribute);
            if (!Instance.IsRegionMapped(AttributesPtr + Offset, HandleAttributeSize))
                return null;

            ulong Handle = Instance._emulator.ReadMemoryULong(AttributesPtr + Offset + 0x08);
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

            if (ReadU32(Reply, OffMessageId) != 0)
                return;

            lock (SyncRoot)
            {
                WriteU32(Reply, OffMessageId, NextMessageId++);
                if (NextMessageId == 0)
                    NextMessageId = 1;
            }
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