using System;
using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The part of the Service Control Manager MMDevApi reaches before it registers an endpoint notification callback.
    public static class ScmPortHandler
    {
        public const string PortName = "\\RPC Control\\ntsvcs";

        // Opnums from this build's sechost, not MS-SCMR. OpenSCManagerW is 64 here, not 15.
        private const uint ProcCloseServiceHandle = 0;
        private const uint ProcOpenServiceW = 16;
        private const uint ProcQueryServiceConfigInternal = 55;
        private const uint ProcOpenSCManagerW = 64;

        private const int ContextHandleSize = 20;
        private const int HandleTagOffset = 4;
        private const uint HandleTag = 0x4D435342;

        private const int OffsetAfterHandle = ContextHandleSize;
        private const int ConformantStringHeaderSize = 12;
        private const int MaximumServiceNameLength = 256;

        private const uint ErrorSuccess = 0;
        private const uint ErrorServiceDoesNotExist = 1060;

        private const uint UniquePointerReferent = 0x20000;

        // WNF state name: version 1, temporary lifetime, system scope. Nothing ever publishes it.
        private const ulong ServiceStateName = (1UL | (3UL << 4) | (1UL << 11)) ^ 0x41C64E6DA3BC0074UL;

        private static readonly string[] KnownServices =
        {
            "AudioSrv",
            "AudioEndpointBuilder",
        };

        // Other interfaces share this port, so anything not served here returns false.
        public static bool TryHandle(string Port, uint ProcNumber, ReadOnlySpan<byte> Stub, out byte[] Reply)
        {
            Reply = null;

            if (!string.Equals(Port, PortName, StringComparison.OrdinalIgnoreCase))
                return false;

            switch (ProcNumber)
            {
                case ProcOpenSCManagerW:
                    Reply = BuildHandleReply(true, ErrorSuccess);
                    return true;

                case ProcOpenServiceW:
                    return TryOpenService(Stub, out Reply);

                case ProcQueryServiceConfigInternal:
                    return TryQueryServiceConfig(Stub, out Reply);

                case ProcCloseServiceHandle:
                    if (!IsOwnHandle(Stub))
                        return false;

                    Reply = BuildHandleReply(false, ErrorSuccess);
                    return true;
            }

            return false;
        }

        private static bool TryOpenService(ReadOnlySpan<byte> Stub, out byte[] Reply)
        {
            Reply = null;

            if (!IsOwnHandle(Stub) || !TryReadServiceName(Stub, out string Name))
                return false;

            bool Known = Array.Exists(KnownServices, Entry => string.Equals(Entry, Name, StringComparison.OrdinalIgnoreCase));
            Reply = BuildHandleReply(Known, Known ? ErrorSuccess : ErrorServiceDoesNotExist);
            return true;
        }

        private static bool TryQueryServiceConfig(ReadOnlySpan<byte> Stub, out byte[] Reply)
        {
            Reply = null;

            if (!IsOwnHandle(Stub) || Stub.Length < OffsetAfterHandle + 4)
                return false;

            uint InfoLevel = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(OffsetAfterHandle, 4));

            // A switch_is union on the info level, then a unique pointer to the arm. Every arm opens with the WNF state name.
            Reply = new byte[20];
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(0, 4), InfoLevel);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(4, 4), UniquePointerReferent);
            BinaryPrimitives.WriteUInt64LittleEndian(Reply.AsSpan(8, 8), ServiceStateName);
            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(16, 4), ErrorSuccess);
            return true;
        }

        private static bool TryReadServiceName(ReadOnlySpan<byte> Stub, out string Name)
        {
            Name = null;

            if (Stub.Length < OffsetAfterHandle + ConformantStringHeaderSize)
                return false;

            ReadOnlySpan<byte> Header = Stub.Slice(OffsetAfterHandle, ConformantStringHeaderSize);
            uint MaximumCount = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0, 4));
            uint Offset = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(4, 4));
            uint ActualCount = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(8, 4));

            if (Offset != 0 || ActualCount == 0 || ActualCount != MaximumCount || ActualCount > MaximumServiceNameLength)
                return false;

            int Bytes = (int)ActualCount * sizeof(char);
            int Start = OffsetAfterHandle + ConformantStringHeaderSize;
            if (Stub.Length < Start + Bytes)
                return false;

            Name = Encoding.Unicode.GetString(Stub.Slice(Start, Bytes)).TrimEnd('\0');
            return Name.Length != 0;
        }

        private static bool IsOwnHandle(ReadOnlySpan<byte> Stub)
        {
            return Stub.Length >= ContextHandleSize
                && BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HandleTagOffset, 4)) == HandleTag;
        }

        private static byte[] BuildHandleReply(bool Opened, uint Status)
        {
            byte[] Reply = new byte[ContextHandleSize + 4];

            if (Opened)
                BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(HandleTagOffset, 4), HandleTag);

            BinaryPrimitives.WriteUInt32LittleEndian(Reply.AsSpan(ContextHandleSize, 4), Status);
            return Reply;
        }
    }
}
