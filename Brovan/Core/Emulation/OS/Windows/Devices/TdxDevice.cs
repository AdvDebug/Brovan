using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class TdxDevice
    {
        private const uint FileDeviceNetwork = 0x12;
        private const uint FileDeviceTransport = 0x21;
        private const uint MethodBuffered = 0;
        private const uint MethodNeither = 3;
        private const uint FileWriteAccess = 2;

        private const uint IoctlTcpQueryInformationEx = (FileDeviceNetwork << 16) | MethodNeither;
        private const uint IoctlTcpSetInformationEx = (FileDeviceNetwork << 16) | (FileWriteAccess << 14) | (1 << 2) | MethodBuffered;
        private const uint IoctlTcpWshSetInformationEx = (FileDeviceNetwork << 16) | (10 << 2) | MethodBuffered;
        private const uint IoctlTdiTlIoControlEndpoint = (FileDeviceTransport << 16) | (14 << 2) | MethodBuffered;
        private const uint IoctlTdiQueryDirectSendHandler = (FileDeviceTransport << 16) | (0x80 << 2) | MethodNeither;
        private const uint IoctlTdiQueryDirectSendDgHandler = (FileDeviceTransport << 16) | (0x81 << 2) | MethodNeither;

        private const uint GenericEntity = 0;
        private const uint ClNlEntity = 0x301;
        private const uint IfEntity = 0x200;
        private const uint AtEntity = 0x280;
        private const uint ErEntity = 0x380;
        private const uint CoTlEntity = 0x400;
        private const uint ClTlEntity = 0x401;

        private const uint InfoClassGeneric = 0x100;
        private const uint InfoClassProtocol = 0x200;
        private const uint InfoTypeProvider = 0x100;
        private const uint EntityListId = 0;
        private const uint EntityTypeId = 1;
        private const uint IfMibStatsId = 1;
        private const uint IpMibStatsId = 1;
        private const uint IpMibAddrtableEntryId = 0x102;
        private const uint IpIntfinfoId = 0x103;

        private const uint CoTlTcp = 0x404;
        private const uint ClTlUdp = 0x403;
        private const uint ErIcmp = 0x380;

        private const int QueryInputSize = 40;
        private const int IfEntrySize = 92;
        private const int IpSnmpInfoSize = 92;
        private const int IpAddrEntrySize = 24;
        private const int EndpointRequestSize64 = 0x30;
        private const int EndpointRequestSize32 = 28;

        // The fixed entities that TdxInitializeEntityArray registers.
        private static readonly (uint Entity, uint Instance)[] FixedEntities =
        {
            (CoTlEntity, 0), (ClTlEntity, 0), (ClNlEntity, 0), (ClNlEntity, 1), (ErEntity, 0), (ErEntity, 1),
        };

        // O:BAG:SYD:(A;;FX;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FX;;;RC), as tdx gives each transport device.
        internal static readonly byte[] Descriptor = NtAccessCheck.BuildSelfRelative(
            NtQueryInformationToken.AdministratorsSid, NtQueryInformationToken.LocalSystemSid,
            NtAccessCheck.BuildAcl(
                NtAccessCheck.AceEntry.Allow(NtQueryInformationToken.EveryoneSid, NtCreateFile.FileGenericMapping.GenericExecute),
                NtAccessCheck.AceEntry.Allow(NtQueryInformationToken.LocalSystemSid, NtCreateFile.FileGenericMapping.GenericAll),
                NtAccessCheck.AceEntry.Allow(NtQueryInformationToken.AdministratorsSid, NtCreateFile.FileGenericMapping.GenericAll),
                NtAccessCheck.AceEntry.Allow(NtQueryInformationToken.RestrictedCodeSid, NtCreateFile.FileGenericMapping.GenericExecute)),
            ReadOnlySpan<byte>.Empty);

        private static readonly WinDeviceDelegate Ipv4Handler = (uint IOCTL, ref DeviceData Data, BinaryEmulator Instance) => Handle(IOCTL, ref Data, Instance, false);
        private static readonly WinDeviceDelegate Ipv6Handler = (uint IOCTL, ref DeviceData Data, BinaryEmulator Instance) => Handle(IOCTL, ref Data, Instance, true);

        // A control channel open completes with Information 0.
        internal static NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, bool Ipv6, out string InternalPath, out WinDeviceDelegate Handler,
            out ulong Information)
        {
            Information = 0;
            InternalPath = DevicePath;
            Handler = Ipv6 ? Ipv6Handler : Ipv4Handler;
            if (EaBuffer.Length == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[!] {DevicePath}: TDI address and connection objects are not modeled.", LogFlags.Issues);
            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        private static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance, bool Ipv6)
        {
            Data.Information = 0;
            Data.OutputBuffer = null;

            if (IOCTL >> 16 == FileDeviceTransport && IOCTL < IoctlTdiTlIoControlEndpoint)
                return ReportUnmodeled(Instance, $"TDI request 0x{IOCTL:X}");

            switch (IOCTL)
            {
                case IoctlTcpQueryInformationEx:
                    return Query(ref Data, Instance, Ipv6);
                case IoctlTcpSetInformationEx:
                case IoctlTcpWshSetInformationEx:
                    return ReportUnmodeled(Instance, $"set request 0x{IOCTL:X}");
                case IoctlTdiTlIoControlEndpoint:
                    return Data.InputLength < (Instance.WinHelper.PointerSize == 8 ? EndpointRequestSize64 : EndpointRequestSize32)
                        ? NTSTATUS.STATUS_INVALID_BUFFER_SIZE
                        : NTSTATUS.STATUS_INVALID_PARAMETER;
                case IoctlTdiQueryDirectSendHandler:
                case IoctlTdiQueryDirectSendDgHandler:
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;
                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
        }

        // The input is a TDIObjectID and 16 bytes of context on both guest widths (TdxTcpQueryInformationEx).
        private static NTSTATUS Query(ref DeviceData Data, BinaryEmulator Instance, bool Ipv6)
        {
            if (Data.InputLength < QueryInputSize || Data.InputLength > int.MaxValue || Data.OutputLength == 0 || Data.InputBuffer == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (Data.UserBuffer == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Locked = Instance.WinHelper.ProbeForWrite(Data.UserBuffer, Data.OutputLength);
            if (Locked != NTSTATUS.STATUS_SUCCESS)
                return Locked;

            ReadOnlySpan<byte> Input = Data.InputBuffer.AsSpan(0, QueryInputSize);
            uint Entity = BinaryPrimitives.ReadUInt32LittleEndian(Input);
            uint EntityInstance = BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(4));
            uint Class = BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(8));
            uint Type = BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(12));
            uint Id = BinaryPrimitives.ReadUInt32LittleEndian(Input.Slice(16));

            switch (Entity)
            {
                case ErEntity:
                    if (EntityInstance >= 2)
                        return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
                    return QueryEntityType(ref Data, Instance, Class, Type, Id, ErIcmp);
                case CoTlEntity:
                case ClTlEntity:
                    if (EntityInstance != 0)
                        return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
                    return QueryEntityType(ref Data, Instance, Class, Type, Id, Entity == CoTlEntity ? CoTlTcp : ClTlUdp);
                case ClNlEntity:
                    return QueryIp(ref Data, Instance, EntityInstance, Type, Id, Ipv6);
                case GenericEntity:
                    if (Class != InfoClassGeneric || Type != InfoTypeProvider || Id != EntityListId)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                    return QueryEntityList(ref Data, Instance);
                case IfEntity:
                    if (Type != InfoTypeProvider || Class != InfoClassProtocol || Id != IfMibStatsId)
                        return NTSTATUS.STATUS_NOT_IMPLEMENTED;
                    return QueryInterface(ref Data, Instance, EntityInstance);
                case AtEntity:
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;
                default:
                    return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }
        }

        private static NTSTATUS QueryEntityType(ref DeviceData Data, BinaryEmulator Instance, uint Class, uint Type, uint Id, uint Value)
        {
            if (Class != InfoClassGeneric || Type != InfoTypeProvider || Id != EntityTypeId)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Data.Information = sizeof(uint);
            if (Data.OutputLength < sizeof(uint))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            return Instance.WinHelper.WriteUInt32(Data.UserBuffer, Value) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS QueryEntityList(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            List<(uint Entity, uint Instance)> Entities = new List<(uint, uint)>(FixedEntities);
            foreach ((GuestNetworkInterface _, uint EntityInstance) in InterfaceEntities(Network))
                Entities.Add((IfEntity, EntityInstance));

            uint Size = (uint)Entities.Count * 8;
            Data.Information = Size;
            if (Data.OutputLength < Size)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            byte[] Output = new byte[Size];
            for (int i = 0; i < Entities.Count; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(i * 8), Entities[i].Entity);
                BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(i * 8 + 4), Entities[i].Instance);
            }

            return Instance.WriteMemory(Data.UserBuffer, Output) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        // NT: tdx registers one entity per IP interface, IPv4 then IPv6, skipping the loopback interface. Instances
        // count up from 1 in that order, and the list is walked newest first.
        private static List<(GuestNetworkInterface Interface, uint Instance)> InterfaceEntities(GuestNetworkSnapshot Network)
        {
            List<(GuestNetworkInterface, uint)> Registered = new List<(GuestNetworkInterface, uint)>();
            uint Next = 1;
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                if (Interface.IsLoopback)
                    continue;

                Registered.Add((Interface, Next++));
                Registered.Add((Interface, Next++));
            }

            Registered.Reverse();
            return Registered;
        }

        // The Information of an IFEntry reply is the description length alone.
        private static NTSTATUS QueryInterface(ref DeviceData Data, BinaryEmulator Instance, uint EntityInstance)
        {
            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            GuestNetworkInterface Found = null;
            foreach ((GuestNetworkInterface Interface, uint Registered) in InterfaceEntities(Network))
            {
                if (Registered == EntityInstance)
                {
                    Found = Interface;
                    break;
                }
            }

            if (Found == null)
                return NTSTATUS.STATUS_NOT_FOUND;

            Span<byte> Rw = stackalloc byte[NsiDevice.InterfaceRwSize];
            Span<byte> Dynamic = stackalloc byte[NsiDevice.InterfaceDynamicSize];
            Span<byte> Static = stackalloc byte[NsiDevice.InterfaceStaticSize];
            NsiDevice.FillInterfaceInformation(Found, Rw, Dynamic, Static);

            int DescriptionLength = BinaryPrimitives.ReadUInt16LittleEndian(Static.Slice(4));
            int Size = IfEntrySize + DescriptionLength;
            if (Data.OutputLength < Size)
            {
                Data.Information = (ulong)Size;
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            byte[] Output = new byte[Size];
            Span<byte> Row = Output;
            int PhysicalLength = Math.Min((int)BinaryPrimitives.ReadUInt16LittleEndian(Rw.Slice(536)), 8);
            ulong Speed = BinaryPrimitives.ReadUInt64LittleEndian(Dynamic.Slice(24));

            WriteField(Row, 0, BinaryPrimitives.ReadUInt32LittleEndian(Static));
            WriteField(Row, 1, BinaryPrimitives.ReadUInt32LittleEndian(Static.Slice(520)));
            WriteField(Row, 2, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(16)));
            WriteField(Row, 3, Speed > uint.MaxValue ? uint.MaxValue : (uint)Speed);
            WriteField(Row, 4, (uint)PhysicalLength);
            Rw.Slice(538, PhysicalLength).CopyTo(Row.Slice(20));
            WriteField(Row, 7, BinaryPrimitives.ReadUInt32LittleEndian(Rw.Slice(16)));
            WriteField(Row, 8, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic));
            WriteField(Row, 9, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(40)));
            WriteField(Row, 10, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(80)));
            WriteField(Row, 11, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(88)));
            WriteField(Row, 12, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(96)) + BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(104)));
            WriteField(Row, 13, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(64)));
            WriteField(Row, 14, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(72)));
            WriteField(Row, 15, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(56)));
            WriteField(Row, 16, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(112)));
            WriteField(Row, 17, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(120)));
            WriteField(Row, 18, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(128)) + BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(136)));
            WriteField(Row, 20, BinaryPrimitives.ReadUInt32LittleEndian(Dynamic.Slice(144)));
            WriteField(Row, 22, (uint)DescriptionLength);
            Static.Slice(6, DescriptionLength).CopyTo(Row.Slice(IfEntrySize));

            if (!Instance.WriteMemory(Data.UserBuffer, Output))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = (ulong)DescriptionLength;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteField(Span<byte> Row, int Index, uint Value) => BinaryPrimitives.WriteUInt32LittleEndian(Row.Slice(Index * 4), Value);

        // Entity instance 0 is IPv4 and 1 IPv6.
        private static NTSTATUS QueryIp(ref DeviceData Data, BinaryEmulator Instance, uint EntityInstance, uint Type, uint Id, bool Ipv6Device)
        {
            if (EntityInstance >= 2)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            if (Type != InfoTypeProvider)
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            if (Id == IpMibStatsId)
                return QueryIpStatistics(ref Data, Instance, EntityInstance == 1);

            if (EntityInstance != 0)
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            if (Id == IpMibAddrtableEntryId)
                return QueryAddressTable(ref Data, Instance);
            if (Id == IpIntfinfoId)
                return QueryInterfaceInfo(ref Data, Instance, Ipv6Device);

            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        // IPSNMPInfo, which is MIB_IPSTATS: (field offset, offset in the IP global object's dynamic block).
        private static readonly (int To, int From)[] IpStatisticsCounters =
        {
            (8, 16), (12, 128), (16, 136), (20, 32), (24, 140), (28, 160), (32, 40), (36, 48), (40, 188), (44, 168), (48, 164),
            (56, 148), (60, 152), (64, 156), (68, 176), (72, 180), (76, 184),
        };

        // tdx reads the IP global object and compartment 0 of the IP module, as GetIpStatisticsEx does.
        private static NTSTATUS QueryIpStatistics(ref DeviceData Data, BinaryEmulator Instance, bool Ipv6)
        {
            const uint Forwarding = 1;
            const uint NotForwarding = 2;
            const uint HopLimitUnset = uint.MaxValue;

            if (Data.OutputLength < IpSnmpInfoSize)
            {
                Data.Information = IpSnmpInfoSize;
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
            }

            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            Guid Module = Ipv6 ? NsiDevice.Ipv6ModuleGuid : NsiDevice.Ipv4ModuleGuid;
            NTSTATUS Status = NsiDevice.GetAllOf(Instance, Network, Module, NsiDevice.ObjectIpGlobal, ReadOnlySpan<byte>.Empty, out NsiDevice.NsiRow Global);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;
            Status = NsiDevice.GetAllOf(Instance, Network, Module, NsiDevice.ObjectIpCompartment, stackalloc byte[NsiDevice.IpCompartmentKeySize],
                out NsiDevice.NsiRow Compartment);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            byte[] Output = new byte[IpSnmpInfoSize];
            uint HopLimit = BinaryPrimitives.ReadUInt32LittleEndian(Compartment.Rw.AsSpan(8));
            BinaryPrimitives.WriteUInt32LittleEndian(Output, BinaryPrimitives.ReadUInt32LittleEndian(Compartment.Rw) == NsiDevice.ForwardingDisabled ? NotForwarding : Forwarding);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(4), HopLimit != HopLimitUnset ? HopLimit : BinaryPrimitives.ReadUInt32LittleEndian(Global.Rw.AsSpan(24)));
            foreach ((int To, int From) in IpStatisticsCounters)
                Global.Dynamic.AsSpan(From, sizeof(uint)).CopyTo(Output.AsSpan(To));
            Global.Static.AsSpan(0, sizeof(uint)).CopyTo(Output.AsSpan(52));
            Compartment.Dynamic.AsSpan(0, sizeof(uint)).CopyTo(Output.AsSpan(80));
            Compartment.Dynamic.AsSpan(12, sizeof(uint)).CopyTo(Output.AsSpan(84));
            Compartment.Dynamic.AsSpan(4, sizeof(uint)).CopyTo(Output.AsSpan(88));

            if (!Instance.WriteMemory(Data.UserBuffer, Output))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = IpSnmpInfoSize;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The address in the request context is IPv6 on the IPv6 devices.
        private static NTSTATUS QueryInterfaceInfo(ref DeviceData Data, BinaryEmulator Instance, bool Ipv6)
        {
            const int ContextOffset = 24;
            const int HeaderSize = 16;
            const uint PointToPoint = 1;
            const uint PointToMultipoint = 2;
            const uint Unidirectional = 4;

            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            int Width = Ipv6 ? 16 : 4;
            Guid Module = Ipv6 ? NsiDevice.Ipv6ModuleGuid : NsiDevice.Ipv4ModuleGuid;
            ReadOnlySpan<byte> Address = Data.InputBuffer.AsSpan(ContextOffset, Width);

            // The unicast rows sort by interface LUID first, as the IP interface rows tdx walks do.
            NsiDevice.NsiRow Owner = null;
            foreach (NsiDevice.NsiRow Unicast in NsiDevice.RowsOf(Instance, Network, Module, NsiDevice.ObjectUnicastAddress))
            {
                if (Unicast.Key.AsSpan(sizeof(ulong), Width).SequenceEqual(Address))
                {
                    Owner = Unicast;
                    break;
                }
            }

            if (Owner == null)
                return NTSTATUS.STATUS_NO_MORE_ENTRIES;

            NTSTATUS Status = NsiDevice.GetAllOf(Instance, Network, NsiDevice.NdisModuleGuid, NsiDevice.ObjectInterfaceState, Owner.Key.AsSpan(0, sizeof(ulong)),
                out NsiDevice.NsiRow State);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            int PhysicalLength = BinaryPrimitives.ReadUInt16LittleEndian(State.Dynamic.AsSpan(548));
            if (Data.OutputLength < (uint)(HeaderSize + PhysicalLength))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            // tdx tests the word at +520 of the static block for the point-to-point access types.
            uint Flags = BinaryPrimitives.ReadUInt16LittleEndian(State.Static.AsSpan(520)) switch
            {
                3 => PointToPoint,
                4 => PointToMultipoint,
                _ => 0,
            };
            if (BinaryPrimitives.ReadUInt32LittleEndian(State.Static.AsSpan(528)) != 0)
                Flags |= Unidirectional;

            byte[] Output = new byte[HeaderSize + PhysicalLength];
            BinaryPrimitives.WriteUInt32LittleEndian(Output, Flags);
            State.Dynamic.AsSpan(544, sizeof(uint)).CopyTo(Output.AsSpan(4));
            State.Dynamic.AsSpan(624, sizeof(uint)).CopyTo(Output.AsSpan(8));
            BinaryPrimitives.WriteUInt32LittleEndian(Output.AsSpan(12), (uint)PhysicalLength);
            State.Dynamic.AsSpan(550, PhysicalLength).CopyTo(Output.AsSpan(HeaderSize));

            if (!Instance.WriteMemory(Data.UserBuffer, Output))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Data.Information = (ulong)Output.Length;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // tdx moves each DHCP or random-suffix address after the first row toward the front, in the order it meets them.
        private static NTSTATUS QueryAddressTable(ref DeviceData Data, BinaryEmulator Instance)
        {
            const uint SuffixDhcp = 3;
            const uint SuffixRandom = 5;

            if (!Instance.WinHelper.TryGetNetwork(out GuestNetworkSnapshot Network, out NTSTATUS Parked))
                return Parked;

            List<byte[]> Rows = new List<byte[]>();
            int Preferred = 0;
            foreach (NsiDevice.NsiRow Unicast in NsiDevice.RowsOf(Instance, Network, NsiDevice.Ipv4ModuleGuid, NsiDevice.ObjectUnicastAddress))
            {
                GuestNetworkInterface Interface = NsiDevice.FindInterface(Network, BinaryPrimitives.ReadUInt64LittleEndian(Unicast.Key));
                if (Interface == null)
                    continue;

                if ((ulong)(Rows.Count + 1) * IpAddrEntrySize > Data.OutputLength)
                {
                    Data.Information = (ulong)Rows.Count * IpAddrEntrySize;
                    return WriteRows(Instance, Data.UserBuffer, Rows, NTSTATUS.STATUS_BUFFER_OVERFLOW);
                }

                uint SuffixOrigin = BinaryPrimitives.ReadUInt32LittleEndian(Unicast.Rw.AsSpan(12));
                byte[] Row = BuildAddressRow(Interface.Index, Unicast.Key.AsSpan(8, 4), BinaryPrimitives.ReadUInt32LittleEndian(Unicast.Rw.AsSpan(16)));
                if (Rows.Count != 0 && SuffixOrigin is SuffixDhcp or SuffixRandom && ++Preferred != Rows.Count)
                {
                    Rows.Add(Rows[Preferred - 1]);
                    Rows[Preferred - 1] = Row;
                    continue;
                }

                Rows.Add(Row);
            }

            Data.Information = (ulong)Rows.Count * IpAddrEntrySize;
            return WriteRows(Instance, Data.UserBuffer, Rows, Rows.Count == 0 ? NTSTATUS.STATUS_NO_MORE_ENTRIES : NTSTATUS.STATUS_SUCCESS);
        }

        private static byte[] BuildAddressRow(uint Index, ReadOnlySpan<byte> Address, uint PrefixLength)
        {
            const uint BroadcastLowBit = 1;
            const uint ReassemblySize = 0xFFFF;

            byte[] Row = new byte[IpAddrEntrySize];
            Address.CopyTo(Row);
            BinaryPrimitives.WriteUInt32LittleEndian(Row.AsSpan(4), Index);
            uint Mask = PrefixLength >= 32 ? uint.MaxValue : ~(uint.MaxValue >> (int)PrefixLength);
            BinaryPrimitives.WriteUInt32BigEndian(Row.AsSpan(8), Mask);
            BinaryPrimitives.WriteUInt32LittleEndian(Row.AsSpan(12), BroadcastLowBit);
            BinaryPrimitives.WriteUInt32LittleEndian(Row.AsSpan(16), ReassemblySize);
            return Row;
        }

        private static NTSTATUS WriteRows(BinaryEmulator Instance, ulong Address, List<byte[]> Rows, NTSTATUS Status)
        {
            for (int i = 0; i < Rows.Count; i++)
            {
                if (!Instance.WriteMemory(Address + (ulong)(i * IpAddrEntrySize), Rows[i]))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return Status;
        }

        private static NTSTATUS ReportUnmodeled(BinaryEmulator Instance, string What)
        {
            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[!] TDI {What} is not modeled.", LogFlags.Issues);
            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }
    }

    internal abstract class TdxTransportDevice : IWinDevice
    {
        public abstract string DeviceName { get; }

        protected abstract bool Ipv6 { get; }

        public byte[] SecurityDescriptor => TdxDevice.Descriptor;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler) =>
            TdxDevice.Create(Instance, DevicePath, EaBuffer, Ipv6, out InternalPath, out Handler, out _);

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler,
            out ulong Information) => TdxDevice.Create(Instance, DevicePath, EaBuffer, Ipv6, out InternalPath, out Handler, out Information);
    }

    internal sealed class TcpDevice : TdxTransportDevice
    {
        public override string DeviceName => "\\Device\\Tcp";

        protected override bool Ipv6 => false;
    }

    internal sealed class Tcp6Device : TdxTransportDevice
    {
        public override string DeviceName => "\\Device\\Tcp6";

        protected override bool Ipv6 => true;
    }

    internal sealed class UdpDevice : TdxTransportDevice
    {
        public override string DeviceName => "\\Device\\Udp";

        protected override bool Ipv6 => false;
    }

    internal sealed class Udp6Device : TdxTransportDevice
    {
        public override string DeviceName => "\\Device\\Udp6";

        protected override bool Ipv6 => true;
    }

    internal sealed class RawIpDevice : TdxTransportDevice
    {
        public override string DeviceName => "\\Device\\RawIp";

        protected override bool Ipv6 => false;
    }

    internal sealed class RawIp6Device : TdxTransportDevice
    {
        public override string DeviceName => "\\Device\\RawIp6";

        protected override bool Ipv6 => true;
    }
}
