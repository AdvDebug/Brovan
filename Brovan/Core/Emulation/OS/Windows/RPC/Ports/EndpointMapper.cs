using System;
using System.Buffers.Binary;
using System.Text;
using Brovan.Core.Settings;
using static Brovan.Core.Emulation.OS.Windows.NtQueryInformationToken;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal static class EndpointMapper
    {
        internal static readonly Guid Interface = new Guid("e1af8308-5d1f-11c9-91a4-08002b14a0fa");

        internal readonly record struct Entry(ushort Minor, string Endpoint, WinProcess Server);

        internal readonly record struct RpcInterface(Guid Id, ushort Major, ushort Minor);

        // Opnums from this build's rpcrt4 epmp client.
        private const uint ProcMap = 3;
        private const uint ProcMapAuth = 7;

        private const uint EptSNotRegistered = 0x16C9A0D6;
        private const uint MaxTowers = 500;

        // The floors rpcrt4's TowerConstruct writes for ncalrpc.
        private const ushort NcalrpcFloorCount = 4;
        private const byte UuidProtocol = 0x0D;
        private const byte LrpcProtocol = 0x0C;
        private const byte EndpointProtocol = 0x10;

        // A UUID floor holds the protocol byte, the UUID and the major version on its left side, the minor version on its right.
        private const ushort UuidFloorLeftSize = 1 + 16 + 2;
        private const ushort UuidFloorRightSize = 2;
        private const int UuidFloorSize = 2 + UuidFloorLeftSize + 2 + UuidFloorRightSize;
        private const int ProtocolFloorSize = 2 + 1 + 2 + 2;
        private const int MaxTowerLength = 2000;

        internal static bool RegisterEndpoint(WinSysHelper Helper, RpcInterface Served, string Endpoint, WinProcess Server) =>
            Helper.HostEndpoints.TryAdd((Served.Id, Served.Major), new Entry(Served.Minor, Endpoint, Server));

        internal static byte[] Handle(in LrpcMessage Message, BinaryEmulator Instance)
        {
            if (Message.ProcNumber != ProcMap && Message.ProcNumber != ProcMapAuth)
                return null;

            if (!TryReadRequest(Message.StubData, Message.ProcNumber == ProcMapAuth, out ReadOnlySpan<byte> Tower, out ReadOnlySpan<byte> Sid, out uint Requested))
                return LrpcPacket.BuildFault(Message, LrpcPacket.RpcXBadStubData);

            Entry Found = default;
            bool Mapped = TryReadInterfaceFloor(Tower, out Guid Requesting, out ushort Major, out ushort Minor, out ReadOnlySpan<byte> SyntaxFloor)
                && Instance.WinHelper.HostEndpoints.TryGetValue((Requesting, Major), out Found) && Found.Minor >= Minor
                && (Sid.IsEmpty || ServerHasSid(Found.Server, Sid));
            if (!Mapped && (Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[!] Endpoint mapper: no endpoint for {Requesting} v{Major}.{Minor}.", LogFlags.General);

            uint Count = Mapped && Requested != 0 ? 1u : 0u;
            int TowerLength = Count != 0 ? TowerSize(Found.Endpoint) : 0;
            Ndr20Writer Writer = new Ndr20Writer(0x40 + TowerLength);
            Writer.WriteContextHandle(ReadOnlySpan<byte>.Empty);
            Writer.WriteUInt32(Count);
            Writer.WriteUInt32(Requested);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(Count);
            if (Count != 0)
            {
                Writer.WriteUniqueReferent();
                Writer.WriteUInt32((uint)TowerLength);
                Writer.WriteUInt32((uint)TowerLength);
                WriteTower(Writer.Take(TowerLength), Requesting, Major, Found.Minor, SyntaxFloor, Found.Endpoint);
                Writer.AlignTo(4);
            }

            Writer.WriteUInt32(Count != 0 ? LrpcPacket.RpcOk : EptSNotRegistered);
            return LrpcPacket.BuildResponse(Message, Writer.Written);
        }

        private static bool TryReadRequest(ReadOnlySpan<byte> Stub, bool Auth, out ReadOnlySpan<byte> Tower, out ReadOnlySpan<byte> Sid, out uint Requested)
        {
            Tower = default;
            Sid = default;
            Requested = 0;
            Ndr20Reader Reader = new Ndr20Reader(Stub);
            if (Auth)
            {
                if (!Reader.TryReadGuid(out _) || !TryReadTower(ref Reader, out Tower))
                    return false;

                if (!Reader.TryReadUInt32(out uint SidReferent) || (SidReferent != 0 && (!Reader.TryReadSid(out Sid) || Sid[0] != SidRevision)))
                    return false;
            }
            else
            {
                if (!Reader.TryReadUInt32(out uint ObjectReferent) || (ObjectReferent != 0 && !Reader.TryReadGuid(out _))
                    || !Reader.TryReadUInt32(out uint TowerReferent) || TowerReferent == 0 || !TryReadTower(ref Reader, out Tower))
                    return false;
            }

            return Reader.TryReadContextHandle(out _) && Reader.TryReadUInt32(out Requested) && Requested <= MaxTowers;
        }

        private static bool TryReadTower(scoped ref Ndr20Reader Reader, out ReadOnlySpan<byte> Tower)
        {
            Tower = default;
            return Reader.TryReadUInt32(out uint Conformance) && Reader.TryReadUInt32(out uint Length) && Length == Conformance && Length <= MaxTowerLength
                && Reader.TryReadBytes((int)Length, out Tower);
        }

        private static bool TryReadInterfaceFloor(ReadOnlySpan<byte> Tower, out Guid Requesting, out ushort Major, out ushort Minor, out ReadOnlySpan<byte> SyntaxFloor)
        {
            Requesting = Guid.Empty;
            Major = 0;
            Minor = 0;
            SyntaxFloor = default;
            if (Tower.Length < 2 + 2 * UuidFloorSize + 2 + 1 || BinaryPrimitives.ReadUInt16LittleEndian(Tower) < NcalrpcFloorCount - 1)
                return false;

            ReadOnlySpan<byte> Floor = Tower.Slice(2);
            if (BinaryPrimitives.ReadUInt16LittleEndian(Floor) != UuidFloorLeftSize || Floor[2] != UuidProtocol
                || BinaryPrimitives.ReadUInt16LittleEndian(Floor.Slice(21)) != UuidFloorRightSize)
                return false;

            Requesting = new Guid(Floor.Slice(3, 16));
            Major = BinaryPrimitives.ReadUInt16LittleEndian(Floor.Slice(19));
            Minor = BinaryPrimitives.ReadUInt16LittleEndian(Floor.Slice(23));
            SyntaxFloor = Tower.Slice(2 + UuidFloorSize, UuidFloorSize);
            ReadOnlySpan<byte> Protocol = Tower.Slice(2 + 2 * UuidFloorSize);
            return BinaryPrimitives.ReadUInt16LittleEndian(SyntaxFloor) == UuidFloorLeftSize && SyntaxFloor[2] == UuidProtocol
                && BinaryPrimitives.ReadUInt16LittleEndian(Protocol) == 1 && Protocol[2] == LrpcProtocol;
        }

        // The endpoint floor ends with the ASCII name and a terminating zero.
        private static int TowerSize(string Endpoint) => 2 + 2 * UuidFloorSize + ProtocolFloorSize + 5 + Endpoint.Length + 1;

        private static void WriteTower(Span<byte> Tower, Guid Requesting, ushort Major, ushort Minor, ReadOnlySpan<byte> SyntaxFloor, string Endpoint)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Tower, NcalrpcFloorCount);
            Span<byte> Floor = Tower.Slice(2);
            BinaryPrimitives.WriteUInt16LittleEndian(Floor, UuidFloorLeftSize);
            Floor[2] = UuidProtocol;
            Requesting.TryWriteBytes(Floor.Slice(3, 16));
            BinaryPrimitives.WriteUInt16LittleEndian(Floor.Slice(19), Major);
            BinaryPrimitives.WriteUInt16LittleEndian(Floor.Slice(21), UuidFloorRightSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Floor.Slice(23), Minor);
            SyntaxFloor.CopyTo(Tower.Slice(2 + UuidFloorSize));

            Span<byte> Protocol = Tower.Slice(2 + 2 * UuidFloorSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Protocol, 1);
            Protocol[2] = LrpcProtocol;
            BinaryPrimitives.WriteUInt16LittleEndian(Protocol.Slice(3), 2);

            Span<byte> Address = Protocol.Slice(ProtocolFloorSize);
            BinaryPrimitives.WriteUInt16LittleEndian(Address, 1);
            Address[2] = EndpointProtocol;
            BinaryPrimitives.WriteUInt16LittleEndian(Address.Slice(3), (ushort)(Endpoint.Length + 1));
            Encoding.ASCII.GetBytes(Endpoint, Address.Slice(5));
        }

        // NT: ept_map_auth checks each server against a descriptor whose owner, group and one READ_CONTROL entry are the SID.
        private static bool ServerHasSid(WinProcess Server, ReadOnlySpan<byte> Sid)
        {
            const uint ReadControl = (uint)AccessMask.ReadControl;
            byte[] Descriptor = NtAccessCheck.BuildSingleAllowDescriptor(Sid, Sid, Sid, ReadControl);
            return NtAccessCheck.CheckHost(Descriptor, Server.GetPrimaryToken(), Server, default, ReadControl, default, out _) == NTSTATUS.STATUS_SUCCESS;
        }
    }
}
