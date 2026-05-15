using System;
using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtAlpcSendWaitReceivePort : IWinSyscall
    {
        private const int PortMessageHeaderSize = 0x28;
        private const int OffPmDataLength = 0x00;
        private const int OffPmTotalLength = 0x02;
        private const int OffPmMessageId = 0x18;

        private static readonly object SyncRoot = new object();
        private static readonly Dictionary<string, Queue<byte[]>> PortQueues = new(StringComparer.OrdinalIgnoreCase);
        private static uint NextMessageId = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong PortHandle = Instance.WinHelper.GetArg64(0);
            uint Flags = (uint)Instance.WinHelper.GetArg64(1, true);
            ulong SendMessagePtr = Instance.WinHelper.GetArg64(2);
            ulong SendMessageAttributesPtr = Instance.WinHelper.GetArg64(3);
            ulong ReceiveMessagePtr = Instance.WinHelper.GetArg64(4);
            ulong BufferLengthPtr = Instance.WinHelper.GetArg64(5);
            ulong ReceiveMessageAttributesPtr = Instance.WinHelper.GetArg64(6);
            ulong TimeoutPtr = Instance.WinHelper.GetArg64(7);

            WinPort Port = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle);
            if (Port == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (SendMessagePtr != 0 && !Instance.IsRegionMapped(SendMessagePtr, (ulong)PortMessageHeaderSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReceiveMessagePtr != 0 && !Instance.IsRegionMapped(ReceiveMessagePtr, (ulong)PortMessageHeaderSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong ReceiveBufferLength = 0;
            if (ReceiveMessagePtr != 0)
            {
                if (BufferLengthPtr != 0 && !Instance.IsRegionMapped(BufferLengthPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ReceiveBufferLength = BufferLengthPtr != 0 ? Instance._emulator.ReadMemoryULong(BufferLengthPtr) : 0;
                if (ReceiveBufferLength < (ulong)PortMessageHeaderSize)
                {
                    if (BufferLengthPtr != 0)
                        Instance._emulator.WriteMemory(BufferLengthPtr, (ulong)PortMessageHeaderSize);
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                }

                if (!Instance.IsRegionMapped(ReceiveMessagePtr, ReceiveBufferLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            byte[] SendBytes = null;
            ushort SendTotalLength = 0;

            if (SendMessagePtr != 0)
            {
                Span<byte> SendHeader = stackalloc byte[PortMessageHeaderSize];
                if (!Instance.ReadMemory(SendMessagePtr, SendHeader))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                SendTotalLength = ReadU16(SendHeader, OffPmTotalLength);

                if (SendTotalLength < PortMessageHeaderSize || SendTotalLength > 0xFFFF)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(SendMessagePtr, SendTotalLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                SendBytes = Instance.ReadMemory(SendMessagePtr, SendTotalLength);
            }

            if (ReceiveMessageAttributesPtr != 0 && Instance.IsRegionMapped(ReceiveMessageAttributesPtr, 8))
            {
                Instance._emulator.WriteMemory(ReceiveMessageAttributesPtr + 0, 0u);
                Instance._emulator.WriteMemory(ReceiveMessageAttributesPtr + 4, 0u);
            }

            if (ReceiveMessagePtr != 0)
            {
                byte[] ReplyBytes = null;
                if (SendBytes != null && Port.Handler != null)
                {
                    Port.Handler(Port, SendBytes, out byte[] HandlerReply, Instance);
                    ReplyBytes = HandlerReply ?? SendBytes;
                }
                else if (SendBytes != null)
                {
                    ReplyBytes = SendBytes;
                }

                ulong WriteLength = (ulong)(ReplyBytes?.Length ?? PortMessageHeaderSize);
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
                    Span<byte> EmptyReply = stackalloc byte[PortMessageHeaderSize];
                    FinalizeReplyHeader(EmptyReply, PortMessageHeaderSize);
                    if (!Instance._emulator.WriteMemory(ReceiveMessagePtr, EmptyReply))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (BufferLengthPtr != 0)
                    Instance._emulator.WriteMemory(BufferLengthPtr, WriteLength);

                Instance.TriggerEventMessage($"[+] NtAlpcSendWaitReceivePort: Port=\"{Port.Name}\", Flags=0x{Flags:X}, ReplyLength=0x{WriteLength:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (SendBytes != null)
            {
                lock (SyncRoot)
                {
                    if (!PortQueues.TryGetValue(Port.Name, out Queue<byte[]> Queue))
                    {
                        Queue = new Queue<byte[]>();
                        PortQueues[Port.Name] = Queue;
                    }
                    Queue.Enqueue(SendBytes);
                }

                Instance.TriggerEventMessage($"[+] NtAlpcSendWaitReceivePort: Port=\"{Port.Name}\", Flags=0x{Flags:X}, SentLength=0x{SendBytes.Length:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (ReceiveMessagePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (TimeoutPtr != 0 && Instance.IsRegionMapped(TimeoutPtr, 8))
                return NTSTATUS.STATUS_TIMEOUT;

            return NTSTATUS.STATUS_TIMEOUT;
        }

        private static void FinalizeReplyHeader(Span<byte> Reply, ushort TotalLength)
        {
            if (Reply.Length < PortMessageHeaderSize)
                return;

            WriteU16(Reply, OffPmTotalLength, TotalLength);
            WriteU16(Reply, OffPmDataLength, TotalLength >= PortMessageHeaderSize ? (ushort)(TotalLength - PortMessageHeaderSize) : (ushort)0);

            if (ReadU32(Reply, OffPmMessageId) != 0)
                return;

            lock (SyncRoot)
            {
                WriteU32(Reply, OffPmMessageId, NextMessageId++);
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