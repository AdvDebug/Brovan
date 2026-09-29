using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // The RPCSS object resolver on the endpoint mapper port.
    internal static class RpcssPortHandler
    {
        public const string PortName = "\\RPC Control\\epmapper";

        private static readonly Guid LocalObjectExporter = new Guid("e60c73e6-88f9-11cf-9af1-0020af6e72f4");
        private static readonly Guid Scm = new Guid("412f241e-c12a-11ce-abff-0020af6e7a17");

        // Opnums from this build's combase lclor and scm format strings.
        private const uint ProcConnect = 0;
        private const uint ProcAllocateReservedIds = 3;
        private const uint ProcBulkUpdateOIDs = 4;
        private const uint ProcServerAllocateOXIDAndOIDs = 6;
        private const uint ProcRegisterWindowPropInterface = 6;
        private const uint ProcGetWindowPropInterface = 7;
        private const uint ProcNotifyDragDropStartOrStop = 13;

        private const int BindInterfaceOffset = 0x0C;
        private const int BindContextOffset = 0x24;
        private const int RequestContextOffset = 0x10;

        private const int ProxyDecodeInfoSize = 96;
        private const int PingPeriodSeconds = 120;
        private const uint ScmProcessId = 0x3F8;
        private const uint AuthnLevelConnect = 2;
        private const uint ImpLevelIdentify = 2;
        private const int SecurityDescriptorCount = 5;
        private const uint MaximumIds = 0x100000;

        // NDR carries __int3264 in four bytes.
        private const int HwndOffset = Ndr20Writer.ContextHandleSize;
        private const int StdObjRefOffset = HwndOffset + 4;
        private const int RevokeOffset = HwndOffset + 8;

        private const uint OrOk = 0;

        private static readonly Dictionary<(ulong Connection, uint Context), Guid> Contexts = new Dictionary<(ulong Connection, uint Context), Guid>();
        private static readonly Dictionary<uint, byte[]> WindowProps = new Dictionary<uint, byte[]>();
        private static readonly Guid ResolverHandle = Guid.NewGuid();
        private static readonly Guid ProcessIdentifier = Guid.NewGuid();
        private static readonly ulong ProcessSignature = (ulong)Random.Shared.NextInt64(1, long.MaxValue);
        private static readonly ulong LocalMachineId = (ulong)Random.Shared.NextInt64(1, long.MaxValue);
        private static ulong NextId = 0x1000;
        private static uint NextCookie = 1;

        public static bool TryHandle(string Port, ulong Connection, in LrpcMessage Message, uint ProcessId, out byte[] Reply)
        {
            Reply = null;

            if (!string.Equals(Port, PortName, StringComparison.OrdinalIgnoreCase))
                return false;

            ReadOnlySpan<byte> Payload = Message.Raw.AsSpan(Math.Min(LrpcPacket.HeaderSize, Message.Raw.Length));

            if (Message.Type == LrpcMessageType.Bind)
            {
                if (Payload.Length < BindContextOffset + 4)
                    return false;

                Guid Interface = new Guid(Payload.Slice(BindInterfaceOffset, 16));
                uint Context = BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(BindContextOffset, 4));
                if (Interface != LocalObjectExporter && Interface != Scm)
                    return false;

                Contexts[(Connection, Context)] = Interface;
                Reply = LrpcPacket.BuildBindAccept(Message, out _);
                return Reply != null;
            }

            if (Message.Type != LrpcMessageType.Request || Payload.Length < RequestContextOffset + 4)
                return false;

            uint RequestContext = BinaryPrimitives.ReadUInt32LittleEndian(Payload.Slice(RequestContextOffset, 4));
            if (!Contexts.TryGetValue((Connection, RequestContext), out Guid Target))
                return false;

            byte[] Stub = null;
            if (Target == LocalObjectExporter)
                Stub = HandleLocalObjectExporter(Message.ProcNumber, Message.StubData, ProcessId);
            else if (Target == Scm)
                Stub = HandleScm(Message.ProcNumber, Message.StubData);

            if (Stub == null)
                return false;

            Reply = LrpcPacket.BuildResponse(Message, Stub);
            return true;
        }

        private static byte[] HandleLocalObjectExporter(uint ProcNumber, ReadOnlySpan<byte> Stub, uint ProcessId)
        {
            switch (ProcNumber)
            {
                case ProcConnect:
                    return Connect(Stub, ProcessId);

                case ProcAllocateReservedIds:
                    return AllocateReservedIds(Stub);

                case ProcBulkUpdateOIDs:
                    return BulkUpdateOIDs(Stub);

                case ProcServerAllocateOXIDAndOIDs:
                    return ServerAllocateOXIDAndOIDs(Stub);
            }

            return null;
        }

        private static byte[] HandleScm(uint ProcNumber, ReadOnlySpan<byte> Stub)
        {
            switch (ProcNumber)
            {
                case ProcRegisterWindowPropInterface:
                    return RegisterWindowPropInterface(Stub);

                case ProcGetWindowPropInterface:
                    return GetWindowPropInterface(Stub);

                case ProcNotifyDragDropStartOrStop:
                    return BuildStatusAndResult(OrOk, 0);
            }

            return null;
        }

        private static byte[] Connect(ReadOnlySpan<byte> Stub, uint ProcessId)
        {
            if (!TryReadConnectIdCount(Stub, out uint IdCount))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(512);

            Writer.WriteContextHandle(ResolverHandle);
            Writer.WriteUInt32(PingPeriodSeconds);

            Writer.WriteUniqueReferent();
            WriteEmptyDualStringArray(ref Writer);

            Writer.WriteUInt64(LocalMachineId);

            Writer.AlignTo(4);
            Writer.WriteUInt32(IdCount);
            Writer.AlignTo(8);
            for (uint i = 0; i < IdCount; i++)
                Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(IdCount);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(AuthnLevelConnect);
            Writer.WriteUInt32(ImpLevelIdentify);

            // No security packages and no channel hooks: a zero count and a null list each.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);

            Writer.WriteUInt32(ProcessId);
            Writer.WriteUInt32(ScmProcessId);
            Writer.WriteUInt64(ProcessSignature);

            Span<byte> Identifier = stackalloc byte[16];
            ProcessIdentifier.TryWriteBytes(Identifier);
            Writer.AlignTo(4);
            Writer.WriteBytes(Identifier);

            // Five self-relative descriptors, each granting Everyone.
            byte[] Descriptor = BuildEveryoneDescriptor();
            uint DescriptorsSize = (uint)(Descriptor.Length * SecurityDescriptorCount);
            for (int i = 0; i < SecurityDescriptorCount; i++)
                Writer.WriteUInt32((uint)Descriptor.Length);

            Writer.WriteUInt32(DescriptorsSize);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(DescriptorsSize);
            for (int i = 0; i < SecurityDescriptorCount; i++)
                Writer.WriteBytes(Descriptor);

            Writer.AlignTo(4);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        // The id array is sized by the in parameter that follows two strings and the proxy decode block.
        private static bool TryReadConnectIdCount(ReadOnlySpan<byte> Stub, out uint IdCount)
        {
            IdCount = 0;

            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (!Reader.TryReadUniqueWideString(out _) || !Reader.TryReadUniqueWideString(out _))
                return false;

            if (!Reader.TryReadUInt32(out uint DecodeInfoReferent))
                return false;

            if (DecodeInfoReferent != 0)
            {
                Reader.Align(8);
                if (!Reader.TrySkip(ProxyDecodeInfoSize))
                    return false;
            }

            if (!Reader.TryReadUInt32(out _) || !Reader.TryReadUInt16(out _))
                return false;

            Reader.Align(4);
            if (!Reader.TryReadUInt32(out IdCount))
                return false;

            return IdCount <= MaximumIds;
        }

        private static bool TryReadIdCount(ReadOnlySpan<byte> Stub, out uint Count)
        {
            Count = 0;

            if (Stub.Length < Ndr20Writer.ContextHandleSize + 4)
                return false;

            Count = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(Ndr20Writer.ContextHandleSize, 4));
            return Count <= MaximumIds;
        }

        private static byte[] AllocateReservedIds(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(32 + (int)Count * 8);
            Writer.WriteUInt32(Count);
            Writer.AlignTo(8);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] BulkUpdateOIDs(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(16 + (int)Count * 4);
            Writer.WriteUInt32(Count);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt32(OrOk);

            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        private static byte[] ServerAllocateOXIDAndOIDs(ReadOnlySpan<byte> Stub)
        {
            if (!TryReadIdCount(Stub, out uint Count))
                return null;

            Ndr20Writer Writer = new Ndr20Writer(64 + (int)Count * 8);
            Writer.WriteUInt64(NextId++);
            Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Count);
            Writer.AlignTo(8);
            for (uint i = 0; i < Count; i++)
                Writer.WriteUInt64(NextId++);

            Writer.WriteUInt32(Count);
            Writer.WriteUInt64(0);

            // No new resolver bindings.
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(OrOk);
            return Writer.ToArray();
        }

        // The STDOBJREF and OXID_INFO go back as marshalled. They are eight byte aligned both ways.
        private static byte[] RegisterWindowPropInterface(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < StdObjRefOffset + 4)
                return null;

            uint Hwnd = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HwndOffset, 4));
            WindowProps[Hwnd] = Stub.Slice(StdObjRefOffset, Stub.Length - 4 - StdObjRefOffset).ToArray();

            Ndr20Writer Writer = new Ndr20Writer(24);
            Writer.WriteUInt32(NextCookie++);
            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        private static byte[] GetWindowPropInterface(ReadOnlySpan<byte> Stub)
        {
            if (Stub.Length < RevokeOffset + 4)
                return null;

            uint Hwnd = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(HwndOffset, 4));
            bool Revoke = BinaryPrimitives.ReadUInt32LittleEndian(Stub.Slice(RevokeOffset, 4)) != 0;

            if (!WindowProps.TryGetValue(Hwnd, out byte[] Registration))
                return null;

            if (Revoke)
                WindowProps.Remove(Hwnd);

            Ndr20Writer Writer = new Ndr20Writer(Registration.Length + 16);
            Writer.WriteBytes(Registration);
            Writer.AlignTo(4);
            Writer.WriteUInt32(OrOk);
            Writer.WriteUInt32(0);
            return Writer.ToArray();
        }

        private static byte[] BuildStatusAndResult(uint Status, uint Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(8);
            Writer.WriteUInt32(Status);
            Writer.WriteUInt32(Result);
            return Writer.ToArray();
        }

        // Empty DUALSTRINGARRAY: each list is only its terminator.
        private static void WriteEmptyDualStringArray(ref Ndr20Writer Writer)
        {
            const ushort Entries = 4;
            const ushort SecurityOffset = 2;

            Writer.WriteUInt32(Entries);
            Writer.WriteUInt16(Entries);
            Writer.WriteUInt16(SecurityOffset);
            for (int i = 0; i < Entries; i++)
                Writer.WriteUInt16(0);

            Writer.AlignTo(4);
        }

        // combase refuses a descriptor without an owner and a group.
        private static byte[] BuildEveryoneDescriptor()
        {
            const ushort SeDaclPresent = 0x0004;
            const ushort SeSelfRelative = 0x8000;
            const int HeaderSize = 20;
            const int AdministratorsSidSize = 16;
            const int AclHeaderSize = 8;
            const int AceHeaderSize = 8;
            const int EveryoneSidSize = 12;
            const int DaclSize = AclHeaderSize + AceHeaderSize + EveryoneSidSize;
            const int OwnerOffset = HeaderSize;
            const int GroupOffset = OwnerOffset + AdministratorsSidSize;
            const int DaclOffset = GroupOffset + AdministratorsSidSize;
            const uint ComRightsExecuteAll = 0x1F;

            byte[] Buffer = new byte[DaclOffset + DaclSize];
            Span<byte> Span = Buffer;

            Span[0] = 1;
            BinaryPrimitives.WriteUInt16LittleEndian(Span.Slice(2, 2), SeDaclPresent | SeSelfRelative);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(4, 4), OwnerOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(8, 4), GroupOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(16, 4), DaclOffset);
            byte[] AdministratorsSid = NtQueryInformationToken.BuildSid(1, 5, 32, 544);
            AdministratorsSid.CopyTo(Span.Slice(OwnerOffset, AdministratorsSidSize));
            AdministratorsSid.CopyTo(Span.Slice(GroupOffset, AdministratorsSidSize));

            Span<byte> Acl = Span.Slice(DaclOffset);
            Acl[0] = 2;
            BinaryPrimitives.WriteUInt16LittleEndian(Acl.Slice(2, 2), DaclSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Acl.Slice(4, 2), 1);

            Span<byte> Ace = Acl.Slice(AclHeaderSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Ace.Slice(2, 2), AceHeaderSize + EveryoneSidSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Ace.Slice(4, 4), ComRightsExecuteAll);

            NtQueryInformationToken.BuildSid(1, 1, 0).CopyTo(Ace.Slice(AceHeaderSize, EveryoneSidSize));
            return Buffer;
        }
    }
}
