using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed partial class NsiDevice
    {
        internal const uint ObjectInterfaceState = 1;
        internal const uint ObjectBestRoute = 0;
        internal const uint ObjectIpCompartment = 2;
        internal const uint ObjectIpGlobal = 6;
        private const uint ObjectIpInterface = 7;
        private const uint ObjectAnycastAddress = 8;
        private const uint ObjectMulticastAddress = 9;
        internal const uint ObjectUnicastAddress = 10;
        private const uint ObjectRoute = 16;

        internal const int BestRouteKeySize4 = 32;
        internal const int BestRouteKeySize6 = 56;
        internal const int BestRouteSourceOffset4 = 96;
        internal const int BestRouteSourceOffset6 = 132;
        private const int BestRouteDynamicSize4 = 104;
        private const int BestRouteDynamicSize6 = 152;
        private const int RouteHeadSize = 28;
        private const int AddressKeySize4 = 16;
        private const int AddressKeySize6 = 24;
        private const int RouteKeySize4 = 48;
        private const int RouteKeySize6 = 72;
        private const int RouteDynamicSize4 = 20;
        private const int RouteDynamicSize6 = 32;
        internal const int IpCompartmentKeySize = 4;
        private const int IpCompartmentRwSize = 16;
        private const int IpCompartmentDynamicSize = 16;
        private const int IpGlobalRwSize = 156;
        private const int IpGlobalDynamicSize = 208;
        private const int IpGlobalStaticSize = 4;
        internal const uint DefaultHopLimit = 128;
        internal const uint ForwardingDisabled = 1;

        private const int StateDynamicSize = 656;
        private const int StateStaticSize = 568;
        private const int IpInterfaceRwSize = 240;
        private const int IpInterfaceDynamicSize = 88;
        private const int IpInterfaceStaticSize = 32;
        private const int UnicastRwSize = 28;
        private const int UnicastDynamicSize = 8;
        private const int UnicastStaticSize = 8;
        private const int RouteRwSize = 32;
        private const int RouteStaticSize = 8;

        private const uint InfiniteLifetime = uint.MaxValue;
        private const uint DadStatePreferred = 4;
        private const uint RouteProtocolLocal = 2;
        private const uint RouteProtocolNetMgmt = 3;
        private const uint RouteOriginWellKnown = 1;
        private const uint LocalRouteMetric = 256;
        private const uint RouteCompartment = 1;

        // NT's automatic interface metrics for loopback and for a 1 Gb/s Ethernet link.
        private const uint LoopbackMetric = 75;
        private const uint EthernetMetric = 25;

        private static NsiObject InterfaceStateObject() => new NsiObject
        {
            Module = NdisModuleGuid,
            Object = ObjectInterfaceState,
            Parameter = ParameterSupport.ThroughGetAll,
            KeySize = sizeof(ulong),
            DynamicSize = StateDynamicSize,
            StaticSize = StateStaticSize,
            ServesAll = true,
            CountOnlyStatus = NTSTATUS.STATUS_MORE_ENTRIES,
            Rows = BuildInterfaceStateRows,
        };

        private static NsiObject ThreadCompartmentObject() => new NsiObject
        {
            Module = NdisModuleGuid,
            Object = ObjectThreadCompartment,
            RwSize = ThreadRwSize,
            ServesAll = true,
            Rows = static (_, _) => new[] { new NsiRow { Key = Array.Empty<byte>(), Rw = BitConverter.GetBytes((ulong)DefaultCompartmentId) } },
        };

        private static NsiObject IpInterfaceObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Parameter = ParameterSupport.ThroughGetAll,
            Object = ObjectIpInterface,
            KeySize = sizeof(ulong),
            RwSize = IpInterfaceRwSize,
            DynamicSize = IpInterfaceDynamicSize,
            StaticSize = IpInterfaceStaticSize,
            ServesAll = true,
            KeyOrder = CompareKeyBytes,
            Rows = (_, Network) => BuildIpInterfaceRows(Network, Module == Ipv6ModuleGuid).ToArray(),
        };

        private static NsiObject UnicastObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Parameter = ParameterSupport.ThroughGetAll,
            Object = ObjectUnicastAddress,
            KeySize = Module == Ipv6ModuleGuid ? AddressKeySize6 : AddressKeySize4,
            RwSize = UnicastRwSize,
            DynamicSize = UnicastDynamicSize,
            StaticSize = UnicastStaticSize,
            ServesAll = true,
            KeyOrder = CompareKeyBytes,
            Rows = (_, Network) => BuildUnicastRows(Network, Module == Ipv6ModuleGuid).ToArray(),
        };

        private static NsiObject AnycastObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Object = ObjectAnycastAddress,
            Parameter = ParameterSupport.ThroughGetAll,
            KeySize = Module == Ipv6ModuleGuid ? AddressKeySize6 : AddressKeySize4,
            ServesAll = true,
            KeyOrder = CompareKeyBytes,
            Rows = static (_, _) => Array.Empty<NsiRow>(),
        };

        private static NsiObject MulticastObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Object = ObjectMulticastAddress,
            Parameter = ParameterSupport.ThroughGetAll,
            KeySize = Module == Ipv6ModuleGuid ? AddressKeySize6 : AddressKeySize4,
            DynamicSize = 12,
            StaticSize = 4,
            ServesAll = true,
            KeyOrder = CompareKeyBytes,
            Rows = (_, Network) => BuildMulticastRows(Network, Module == Ipv6ModuleGuid).ToArray(),
        };

        // The groups NT joins on a connected interface. Loopback joins none.
        private static List<NsiRow> BuildMulticastRows(GuestNetworkSnapshot Network, bool Ipv6)
        {
            List<NsiRow> Rows = new List<NsiRow>();
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                if (Interface.IsLoopback || !Interface.Connected)
                    continue;

                List<byte[]> Groups = new List<byte[]>();
                if (Ipv6)
                {
                    Groups.Add(new byte[] { 0xFF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
                    Groups.Add(new byte[] { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
                    foreach (GuestNetworkAddress Address in Interface.Addresses)
                    {
                        if (Address.IsIPv4)
                            continue;

                        byte[] Bytes = Address.Address.GetAddressBytes();
                        Groups.Add(new byte[] { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, Bytes[13], Bytes[14], Bytes[15] });
                    }
                }
                else
                {
                    Groups.Add(new byte[] { 224, 0, 0, 1 });
                }

                foreach (byte[] Group in Groups)
                {
                    byte[] Key = new byte[Ipv6 ? AddressKeySize6 : AddressKeySize4];
                    BinaryPrimitives.WriteUInt64LittleEndian(Key, Interface.Luid);
                    Group.CopyTo(Key, 8);
                    if (ContainsKey(Rows, Key))
                        continue;

                    byte[] Dynamic = new byte[12];
                    Put(Dynamic, 0, Interface.Index);
                    Put(Dynamic, 8, 1);
                    Rows.Add(new NsiRow { Key = Key, Dynamic = Dynamic, Static = BitConverter.GetBytes(Interface.Index) });
                }
            }

            return Rows;
        }

        private static NsiObject RouteObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Object = ObjectRoute,
            Parameter = ParameterSupport.ThroughGetAll,
            KeySize = Module == Ipv6ModuleGuid ? RouteKeySize6 : RouteKeySize4,
            RwSize = RouteRwSize,
            DynamicSize = Module == Ipv6ModuleGuid ? RouteDynamicSize6 : RouteDynamicSize4,
            StaticSize = RouteStaticSize,
            ServesAll = true,
            KeyOrder = CompareKeyBytes,
            Rows = (Instance, Network) => BuildRouteRows(Instance, Network, Module == Ipv6ModuleGuid).ToArray(),
        };

        private static void Put(Span<byte> Block, int Offset, uint Value) => BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(Offset), Value);

        private static bool ContainsKey(List<NsiRow> Rows, byte[] Key)
        {
            foreach (NsiRow Existing in Rows)
            {
                if (Existing.Key.AsSpan().SequenceEqual(Key))
                    return true;
            }

            return false;
        }

        // The interface state is the dynamic and static parts of the interface object, without its counters.
        private static NsiRow[] BuildInterfaceStateRows(BinaryEmulator Instance, GuestNetworkSnapshot Network)
        {
            NsiRow[] Rows = new NsiRow[Network.Interfaces.Length];
            for (int i = 0; i < Rows.Length; i++)
            {
                GuestNetworkInterface Interface = Network.Interfaces[i];
                byte[] Dynamic = new byte[StateDynamicSize];
                byte[] Static = new byte[StateStaticSize];

                Put(Dynamic, 0, 1);
                Interface.NetworkGuid.TryWriteBytes(Dynamic.AsSpan(4));
                WriteCountedString(Dynamic.AsSpan(20, CountedStringSize), Interface.Alias);
                Put(Dynamic, 536, Interface.Connected ? OperUp : OperDown);
                Put(Dynamic, 540, Interface.Connected ? 0 : NotMediaConnected);
                Put(Dynamic, 544, Interface.Mtu);
                WritePhysicalAddress(Dynamic.AsSpan(548, PhysicalAddressSize), Interface.PhysicalAddress);
                WritePhysicalAddress(Dynamic.AsSpan(582, PhysicalAddressSize), Interface.PhysicalAddress);
                Put(Dynamic, 616, Interface.Connected ? MediaConnected : MediaDisconnected);
                BinaryPrimitives.WriteUInt64LittleEndian(Dynamic.AsSpan(624), Interface.LinkSpeed);
                BinaryPrimitives.WriteUInt64LittleEndian(Dynamic.AsSpan(632), Interface.LinkSpeed);
                Put(Dynamic, 644, 1);
                Put(Dynamic, 648, FullDuplex);

                Put(Static, 0, Interface.Index);
                WriteCountedString(Static.AsSpan(4, CountedStringSize), Interface.Description);
                Put(Static, 520, Interface.Type);
                Put(Static, 524, Interface.AccessType);
                Put(Static, 532, DedicatedConnection);
                Interface.InterfaceGuid.TryWriteBytes(Static.AsSpan(536));
                Put(Static, 552, Interface.Hardware ? 1u : 0u);
                Put(Static, 556, Interface.Hardware ? 1u : 0u);
                Put(Static, 560, Interface.MediaType);
                Put(Static, 564, Interface.PhysicalMediumType);

                Rows[i] = new NsiRow { Key = BitConverter.GetBytes(Interface.Luid), Dynamic = Dynamic, Static = Static };
            }

            return Rows;
        }

        // The values are what tcpip.sys reports for a loopback and for an Ethernet interface.
        private static List<NsiRow> BuildIpInterfaceRows(GuestNetworkSnapshot Network, bool Ipv6)
        {
            const uint BaseReachableTime = 30000;
            const uint RetransmitTime = 1000;
            const uint PathMtuDiscoveryTimeout = 600000;
            const uint LinkLocalTimeout = 6500;
            const uint SitePrefixLength = 64;

            List<NsiRow> Rows = new List<NsiRow>();
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                byte[] Rw = new byte[IpInterfaceRwSize];
                byte[] Dynamic = new byte[IpInterfaceDynamicSize];
                byte[] Static = new byte[IpInterfaceStaticSize];
                bool Loopback = Interface.IsLoopback;

                Put(Rw, 4, Loopback ? 0x10000u : 0x10100u);
                Put(Rw, 8, Ipv6 ? 0 : 0x01010000u);
                Put(Rw, 16, Loopback ? uint.MaxValue : 0);
                Put(Rw, 20, Ipv6 ? 1u : 2u);
                Put(Rw, 28, InterfaceMetric(Interface));
                Put(Rw, 32, BaseReachableTime);
                Put(Rw, 36, RetransmitTime);
                Put(Rw, 40, PathMtuDiscoveryTimeout);
                Put(Rw, 44, Loopback ? 0 : Ipv6 ? 1u : 3u);
                Put(Rw, 48, Ipv6 ? 2u : 1u);
                Put(Rw, 52, Ipv6 ? 0 : LinkLocalTimeout);
                for (int Zone = 0; Zone < 14; Zone++)
                    Put(Rw, 56 + Zone * 4, Zone < 4 ? Interface.Index : 1);
                Put(Rw, 116, 1);
                Put(Rw, 120, Loopback ? uint.MaxValue : Interface.Mtu);
                Put(Rw, 124, Loopback ? SitePrefixLength : 0);
                Put(Rw, 156, 1800);
                Put(Rw, 160, 1);
                Put(Rw, 176, Loopback ? 0 : Ipv6 ? 0x98968Au : 0x989689u);
                Put(Rw, 184, 3);
                Put(Rw, 208, Loopback ? uint.MaxValue : 0);
                Put(Rw, 216, RetransmitTime);
                Put(Rw, 224, 1);
                Put(Rw, 228, Ipv6 ? 0x01010000u : 0);
                Put(Rw, 232, 1);

                Put(Dynamic, 0, Interface.Index);
                Put(Dynamic, 4, 1);
                Put(Dynamic, 12, BaseReachableTime);
                Put(Dynamic, 16, Interface.Connected ? 1u : 0u);
                Put(Dynamic, 32, Loopback ? (Ipv6 ? 0x1C3Cu : 0x1C1Cu) : (Ipv6 ? 0x1CBCu : 0x1FBFu));

                Put(Static, 0, Loopback ? 0x00010000u : 0x00010101u);
                Put(Static, 4, Interface.Type);
                if (!Loopback)
                {
                    Put(Static, 16, 0x06000000);
                    Put(Static, 20, 0x00060080);
                }

                Rows.Add(new NsiRow { Key = BitConverter.GetBytes(Interface.Luid), Rw = Rw, Dynamic = Dynamic, Static = Static });
            }

            return Rows;
        }

        private static List<NsiRow> BuildUnicastRows(GuestNetworkSnapshot Network, bool Ipv6)
        {
            List<NsiRow> Rows = new List<NsiRow>();
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                foreach (GuestNetworkAddress Address in Interface.Addresses)
                {
                    if (Address.IsIPv4 == Ipv6)
                        continue;

                    byte[] Key = new byte[Ipv6 ? AddressKeySize6 : AddressKeySize4];
                    BinaryPrimitives.WriteUInt64LittleEndian(Key, Interface.Luid);
                    Address.Address.TryWriteBytes(Key.AsSpan(8), out _);

                    byte[] Rw = new byte[UnicastRwSize];
                    Put(Rw, 0, InfiniteLifetime);
                    Put(Rw, 4, InfiniteLifetime);
                    Put(Rw, 8, Address.PrefixOrigin);
                    Put(Rw, 12, Address.SuffixOrigin);
                    Put(Rw, 16, Address.PrefixLength);

                    byte[] Dynamic = new byte[UnicastDynamicSize];
                    Put(Dynamic, 0, Address.Address.IsIPv6LinkLocal ? Interface.Index : 0);
                    Put(Dynamic, 4, DadStatePreferred);

                    Rows.Add(new NsiRow { Key = Key, Rw = Rw, Dynamic = Dynamic, Static = BitConverter.GetBytes(Network.CreatedAt) });
                }
            }

            return Rows;
        }

        // The routes NT adds for a connected interface, and a default route through each gateway.
        private static List<NsiRow> BuildRouteRows(BinaryEmulator Instance, GuestNetworkSnapshot Network, bool Ipv6)
        {
            List<NsiRow> Rows = new List<NsiRow>();
            int Width = Ipv6 ? 16 : 4;
            uint Age = (uint)Math.Min(Instance.EmulatedTickCount64 / 1000, uint.MaxValue);
            Span<byte> Bytes = stackalloc byte[16];
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                if (!Interface.Connected)
                    continue;

                bool Any = false;
                foreach (GuestNetworkAddress Address in Interface.Addresses)
                {
                    if (Address.IsIPv4 == Ipv6)
                        continue;

                    Any = true;
                    Bytes.Clear();
                    Address.Address.TryWriteBytes(Bytes, out _);
                    byte[] Host = Bytes.Slice(0, Width).ToArray();
                    int HostLength = Width * 8;
                    if (Address.PrefixLength < HostLength)
                        AddRoute(Rows, Age, Interface, Ipv6, Prefix(Host, Address.PrefixLength), Address.PrefixLength, null, false, null, RouteProtocolLocal, LocalRouteMetric, 0);
                    AddRoute(Rows, Age, Interface, Ipv6, Host, (byte)HostLength, null, true, Host, RouteProtocolLocal, LocalRouteMetric, 0);
                    if (!Ipv6 && Address.PrefixLength < 31)
                    {
                        byte[] Broadcast = Broadcast4(Host, Address.PrefixLength);
                        AddRoute(Rows, Age, Interface, false, Broadcast, 32, null, true, Broadcast, RouteProtocolLocal, LocalRouteMetric, 0);
                    }
                }

                if (!Any)
                    continue;

                if (Ipv6)
                {
                    AddRoute(Rows, Age, Interface, true, Multicast6, 8, null, false, null, RouteProtocolLocal, LocalRouteMetric, RouteOriginWellKnown);
                }
                else
                {
                    AddRoute(Rows, Age, Interface, false, Multicast4, 4, null, false, null, RouteProtocolLocal, LocalRouteMetric, RouteOriginWellKnown);
                    AddRoute(Rows, Age, Interface, false, LimitedBroadcast, 32, null, true, LimitedBroadcast, RouteProtocolLocal, LocalRouteMetric, 0);
                }

                foreach (IPAddress Gateway in Interface.Gateways)
                {
                    if ((Gateway.AddressFamily == AddressFamily.InterNetworkV6) != Ipv6)
                        continue;

                    AddRoute(Rows, Age, Interface, Ipv6, new byte[Width], 0, Gateway.GetAddressBytes(), false, null, RouteProtocolNetMgmt, 0, 0);
                }
            }

            return Rows;
        }

        private static readonly byte[] Multicast4 = { 224, 0, 0, 0 };
        private static readonly byte[] LimitedBroadcast = { 255, 255, 255, 255 };
        private static readonly byte[] Multicast6 = { 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        private static byte[] Prefix(byte[] Address, int Length)
        {
            byte[] Result = (byte[])Address.Clone();
            for (int Bit = Length; Bit < Result.Length * 8; Bit++)
                Result[Bit / 8] &= (byte)~(0x80 >> (Bit % 8));
            return Result;
        }

        private static byte[] Broadcast4(byte[] Address, int Length)
        {
            byte[] Result = (byte[])Address.Clone();
            for (int Bit = Length; Bit < 32; Bit++)
                Result[Bit / 8] |= (byte)(0x80 >> (Bit % 8));
            return Result;
        }

        // The key is nsi_ipv4_forward_key or nsi_ipv6_forward_key.
        private static void AddRoute(List<NsiRow> Rows, uint Age, GuestNetworkInterface Interface, bool Ipv6, byte[] Destination, byte PrefixLength, byte[] NextHop,
            bool Loopback, byte[] Local, uint Protocol, uint Metric, uint Origin)
        {
            byte[] Key = new byte[Ipv6 ? RouteKeySize6 : RouteKeySize4];
            int LuidOffset = Ipv6 ? 40 : 24;
            Put(Key, 0, RouteCompartment);
            Destination.CopyTo(Key, 4);
            Key[Ipv6 ? 20 : 8] = PrefixLength;
            BinaryPrimitives.WriteUInt64LittleEndian(Key.AsSpan(LuidOffset), Interface.Luid);
            BinaryPrimitives.WriteUInt64LittleEndian(Key.AsSpan(LuidOffset + 8), Interface.Luid);
            NextHop?.CopyTo(Key, LuidOffset + 16);

            if (ContainsKey(Rows, Key))
                return;

            byte[] Rw = new byte[RouteRwSize];
            Put(Rw, 4, InfiniteLifetime);
            Put(Rw, 8, InfiniteLifetime);
            Put(Rw, 12, Metric);
            Put(Rw, 16, Protocol);
            Rw[20] = Loopback ? (byte)1 : (byte)0;
            Rw[21] = Protocol == RouteProtocolLocal ? (byte)1 : (byte)0;
            Put(Rw, 24, 0x00010101);

            // The age in seconds, then the first hop at +16, as IppFillUnicastRouteData writes them.
            byte[] Dynamic = new byte[Ipv6 ? RouteDynamicSize6 : RouteDynamicSize4];
            Put(Dynamic, 0, Age);
            (Local ?? NextHop)?.CopyTo(Dynamic, 16);

            byte[] Static = new byte[RouteStaticSize];
            Put(Static, 0, Origin);
            Put(Static, 4, Interface.Index);

            Rows.Add(new NsiRow { Key = Key, Rw = Rw, Dynamic = Dynamic, Static = Static });
        }

        // The key is the compartment, the destination and its scope, the source and its scope, then the interface LUID.
        private static NsiObject BestRouteObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Object = ObjectBestRoute,
            KeySize = Module == Ipv6ModuleGuid ? BestRouteKeySize6 : BestRouteKeySize4,
            DynamicSize = Module == Ipv6ModuleGuid ? BestRouteDynamicSize6 : BestRouteDynamicSize4,
            ServesAll = true,
            Parameter = ParameterSupport.ThroughGetAll,
            Lookup = LookupBestRoute,
        };

        private static NsiObject IpCompartmentObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Object = ObjectIpCompartment,
            KeySize = IpCompartmentKeySize,
            RwSize = IpCompartmentRwSize,
            DynamicSize = IpCompartmentDynamicSize,
            ServesAll = true,
            Parameter = ParameterSupport.ThroughGetAll,
            Rows = (Instance, Network) => new[] { BuildIpCompartmentRow(Instance, Network, Module == Ipv6ModuleGuid) },
            Lookup = LookupIpCompartment,
        };

        private static NsiObject IpGlobalObject(Guid Module) => new NsiObject
        {
            Module = Module,
            Object = ObjectIpGlobal,
            RwSize = IpGlobalRwSize,
            DynamicSize = IpGlobalDynamicSize,
            StaticSize = IpGlobalStaticSize,
            ServesAll = true,
            Parameter = ParameterSupport.ThroughGetAll,
            Rows = (_, Network) => new[] { BuildIpGlobalRow(Network, Module == Ipv6ModuleGuid) },
        };

        private static NTSTATUS LookupIpCompartment(NsiObject Object, BinaryEmulator Instance, GuestNetworkSnapshot Network, uint Action, ReadOnlySpan<byte> Key,
            out NsiRow Row)
        {
            if (Action != ActionGetExact)
                return FindRow(Object, Object.RowsOf(Instance, Network), Action, Key, out Row);

            Row = null;
            if (!IsCallerCompartment(BinaryPrimitives.ReadUInt32LittleEndian(Key)))
                return NTSTATUS.STATUS_NOT_FOUND;

            Row = BuildIpCompartmentRow(Instance, Network, Object.Module == Ipv6ModuleGuid);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The rw block holds the forwarding state and the hop limit. The dynamic block counts interfaces, route prefixes,
        // cached paths and local addresses.
        private static NsiRow BuildIpCompartmentRow(BinaryEmulator Instance, GuestNetworkSnapshot Network, bool Ipv6)
        {
            int Width = Ipv6 ? 16 : 4;
            List<NsiRow> Routes = BuildRouteRows(Instance, Network, Ipv6);
            int Prefixes = 0;
            for (int i = 0; i < Routes.Count; i++)
            {
                bool Seen = false;
                for (int j = 0; j < i && !Seen; j++)
                    Seen = Routes[j].Key.AsSpan(4, Width + 1).SequenceEqual(Routes[i].Key.AsSpan(4, Width + 1));
                Prefixes += Seen ? 0 : 1;
            }

            byte[] Rw = new byte[IpCompartmentRwSize];
            Put(Rw, 0, ForwardingDisabled);
            Put(Rw, 8, DefaultHopLimit);

            byte[] Dynamic = new byte[IpCompartmentDynamicSize];
            Put(Dynamic, 0, (uint)Network.Interfaces.Length);
            Put(Dynamic, 4, (uint)Prefixes);
            Put(Dynamic, 12, (uint)(BuildUnicastRows(Network, Ipv6).Count + BuildMulticastRows(Network, Ipv6).Count));
            return new NsiRow { Key = BitConverter.GetBytes(DefaultCompartmentId), Rw = Rw, Dynamic = Dynamic };
        }

        // NT sizes the reassembly limit at +36 from physical memory.
        private const uint ReassemblyLimit = 0x07D11D60;

        private static readonly (int Offset, uint Value)[] Ipv4GlobalRw =
        {
            (8, 0xFFFFFFFF), (12, 0xFFFFFFFF), (24, DefaultHopLimit), (28, 0x100), (32, 0x1000), (36, ReassemblyLimit), (48, 0x12C), (52, 0x12C), (56, 0x3C),
            (60, 0xA), (64, 1), (88, 1), (92, 2), (96, 4), (100, 0xFFFFFFFF), (104, 0x100), (108, 0x00010001), (112, 0x100), (120, 0x240),
            (124, 0x000A0101), (128, 0x00040100), (136, 0x00200001), (140, 1), (144, 1), (148, 0xFFFFFFFE), (152, 0x01000000),
        };

        private static readonly (int Offset, uint Value)[] Ipv6GlobalRw =
        {
            (0, 1), (4, 0x258), (8, 0x93A80), (12, 0x93A80), (16, 3), (20, 5), (24, DefaultHopLimit), (28, 0x100), (32, 0x1000), (36, ReassemblyLimit),
            (48, 0x12C), (52, 0x12C), (56, 0x3C), (60, 0xA), (64, 2), (88, 1), (92, 2), (96, 4), (100, 0xFFFFFFFF), (104, 0x100),
            (108, 0x00010001), (112, 0x100), (120, 0x500), (124, 0x000A0101), (128, 0x00040101), (136, 0x00200001), (144, 2), (148, 3),
            (152, 0x01000000),
        };

        // The IP counters stay 0, like the interface counters.
        private static NsiRow BuildIpGlobalRow(GuestNetworkSnapshot Network, bool Ipv6)
        {
            const uint NlClients = 5;
            const uint FlProviders = 5;
            const uint ReassemblyTimeout = 60;

            byte[] Rw = new byte[IpGlobalRwSize];
            foreach ((int Offset, uint Value) in Ipv6 ? Ipv6GlobalRw : Ipv4GlobalRw)
                Put(Rw, Offset, Value);

            byte[] Dynamic = new byte[IpGlobalDynamicSize];
            Put(Dynamic, 0, 1);
            Put(Dynamic, 4, NlClients);
            Put(Dynamic, 8, FlProviders);
            Put(Dynamic, 12, (uint)Network.Interfaces.Length);

            return new NsiRow { Key = Array.Empty<byte>(), Rw = Rw, Dynamic = Dynamic, Static = BitConverter.GetBytes(ReassemblyTimeout) };
        }

        // NT picks the longest matching route of lowest metric, then a source address on its interface
        // (IppGetAllBestRouteParameters).
        private static NTSTATUS LookupBestRoute(NsiObject Object, BinaryEmulator Instance, GuestNetworkSnapshot Network, uint Action, ReadOnlySpan<byte> Key,
            out NsiRow Row)
        {
            const uint ZoneMask = 0x0FFFFFFF;

            Row = null;
            if (Action != ActionGetExact)
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            bool Ipv6 = Object.Module == Ipv6ModuleGuid;
            int Width = Ipv6 ? 16 : 4;
            if (!IsCallerCompartment(BinaryPrimitives.ReadUInt32LittleEndian(Key)))
                return NTSTATUS.STATUS_NOT_FOUND;

            ReadOnlySpan<byte> Destination = Key.Slice(4, Width);
            uint DestinationZone = BinaryPrimitives.ReadUInt32LittleEndian(Key.Slice(4 + Width)) & ZoneMask;
            ReadOnlySpan<byte> Source = Key.Slice(8 + Width, Width);
            uint SourceZone = BinaryPrimitives.ReadUInt32LittleEndian(Key.Slice(8 + 2 * Width)) & ZoneMask;
            ulong Luid = BinaryPrimitives.ReadUInt64LittleEndian(Key.Slice(Ipv6 ? 48 : 24));
            bool LinkLocalDestination = IsLinkLocal(Destination);

            if (DestinationZone != 0 && (IsLoopbackAddress(Destination) || (!LinkLocalDestination && DestinationZone != DefaultCompartmentId)))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            List<NsiRow> Addresses = BuildUnicastRows(Network, Ipv6);
            NsiRow Chosen = null;
            GuestNetworkInterface Interface = null;
            if (Source.IndexOfAnyExcept((byte)0) >= 0)
            {
                foreach (NsiRow Address in Addresses)
                {
                    if (Address.Key.AsSpan(8, Width).SequenceEqual(Source)
                        && (SourceZone == 0 || !Ipv6 || !IsLinkLocal(Source) || BinaryPrimitives.ReadUInt32LittleEndian(Address.Dynamic) == SourceZone))
                    {
                        Chosen = Address;
                        break;
                    }
                }

                if (Chosen == null)
                    return NTSTATUS.STATUS_NOT_FOUND;
                Interface = FindInterface(Network, BinaryPrimitives.ReadUInt64LittleEndian(Chosen.Key));
            }
            else if (Luid != 0)
            {
                Interface = FindInterface(Network, Luid);
                if (Interface == null)
                    return NTSTATUS.STATUS_NOT_FOUND;
            }

            if (DestinationZone != 0 && LinkLocalDestination)
            {
                if (Interface != null && Interface.Index != DestinationZone)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                Interface ??= FindInterfaceByIndex(Network, DestinationZone);
                if (Interface == null)
                    return NTSTATUS.STATUS_NOT_FOUND;
            }

            if (Ipv6 && Destination.IndexOfAnyExcept((byte)0) < 0)
                return NTSTATUS.STATUS_NOT_FOUND;

            NsiRow Best = null;
            GuestNetworkInterface BestInterface = null;
            int BestLength = -1;
            uint BestMetric = uint.MaxValue;
            int LuidOffset = Ipv6 ? 40 : 24;
            foreach (NsiRow Route in BuildRouteRows(Instance, Network, Ipv6))
            {
                GuestNetworkInterface Via = FindInterface(Network, BinaryPrimitives.ReadUInt64LittleEndian(Route.Key.AsSpan(LuidOffset)));
                int Length = Route.Key[4 + Width];
                if (Via == null || (Interface != null && Via != Interface) || Length < BestLength || !PrefixMatches(Route.Key.AsSpan(4, Width), Destination, Length))
                    continue;

                uint Metric = BinaryPrimitives.ReadUInt32LittleEndian(Route.Rw.AsSpan(12)) + InterfaceMetric(Via);
                if (Length == BestLength && Metric >= BestMetric)
                    continue;

                Best = Route;
                BestInterface = Via;
                BestLength = Length;
                BestMetric = Metric;
            }

            if (Best == null)
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            ReadOnlySpan<byte> FirstHop = Best.Dynamic.AsSpan(16, Width);
            Chosen ??= PickSourceAddress(Addresses, BestInterface, Destination, FirstHop.IndexOfAnyExcept((byte)0) >= 0 ? FirstHop : Destination);
            if (Chosen == null)
                return NTSTATUS.STATUS_HOST_UNREACHABLE;

            byte[] Dynamic = new byte[Ipv6 ? BestRouteDynamicSize6 : BestRouteDynamicSize4];
            int At = Best.Key.Length;
            Best.Key.CopyTo(Dynamic, 0);
            Best.Rw.AsSpan(0, RouteHeadSize).CopyTo(Dynamic.AsSpan(At));
            At += RouteHeadSize;
            Best.Dynamic.AsSpan(0, sizeof(uint)).CopyTo(Dynamic.AsSpan(At));
            Best.Dynamic.AsSpan(16, Width).CopyTo(Dynamic.AsSpan(At + sizeof(uint)));
            At += sizeof(uint) + Width;
            Best.Static.CopyTo(Dynamic, At);
            At += RouteStaticSize;
            Chosen.Dynamic.AsSpan(0, sizeof(uint)).CopyTo(Dynamic.AsSpan(At));
            Chosen.Key.AsSpan(8, Width).CopyTo(Dynamic.AsSpan(At + sizeof(uint)));

            Row = new NsiRow { Key = Key.ToArray(), Dynamic = Dynamic };
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT prefers the destination itself, then an address on the link of the first hop, then one of the destination's
        // scope, then the longest common prefix.
        private static NsiRow PickSourceAddress(List<NsiRow> Addresses, GuestNetworkInterface Interface, ReadOnlySpan<byte> Destination, ReadOnlySpan<byte> FirstHop)
        {
            NsiRow Picked = null;
            int PickedRank = -1;
            foreach (NsiRow Address in Addresses)
            {
                if (BinaryPrimitives.ReadUInt64LittleEndian(Address.Key) != Interface.Luid)
                    continue;

                ReadOnlySpan<byte> Candidate = Address.Key.AsSpan(8, Destination.Length);
                int OnLinkLength = (int)BinaryPrimitives.ReadUInt32LittleEndian(Address.Rw.AsSpan(16));
                int Rank = Candidate.SequenceEqual(Destination)
                    ? int.MaxValue
                    : (PrefixMatches(Candidate, FirstHop, OnLinkLength) ? 512 : 0) + (IsLinkLocal(Candidate) == IsLinkLocal(Destination) ? 256 : 0)
                      + CommonPrefixLength(Candidate, Destination);
                if (Rank > PickedRank)
                {
                    Picked = Address;
                    PickedRank = Rank;
                }
            }

            return Picked;
        }

        // tcpip takes compartment 0 for the caller's, and the guest has one compartment.
        private static bool IsCallerCompartment(uint Compartment) => Compartment == 0 || Compartment == DefaultCompartmentId;

        private static uint InterfaceMetric(GuestNetworkInterface Interface) => Interface.IsLoopback ? LoopbackMetric : EthernetMetric;

        internal static GuestNetworkInterface FindInterface(GuestNetworkSnapshot Network, ulong Luid)
        {
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                if (Interface.Luid == Luid)
                    return Interface;
            }

            return null;
        }

        private static GuestNetworkInterface FindInterfaceByIndex(GuestNetworkSnapshot Network, uint Index)
        {
            foreach (GuestNetworkInterface Interface in Network.Interfaces)
            {
                if (Interface.Index == Index)
                    return Interface;
            }

            return null;
        }

        private static bool PrefixMatches(ReadOnlySpan<byte> Prefix, ReadOnlySpan<byte> Address, int Length) => CommonPrefixLength(Prefix, Address) >= Length;

        private static int CommonPrefixLength(ReadOnlySpan<byte> Left, ReadOnlySpan<byte> Right)
        {
            for (int i = 0; i < Left.Length; i++)
            {
                int Differ = Left[i] ^ Right[i];
                if (Differ != 0)
                    return i * 8 + BitOperations.LeadingZeroCount((uint)Differ) - 24;
            }

            return Left.Length * 8;
        }

        private static bool IsLoopbackAddress(ReadOnlySpan<byte> Address) =>
            Address.Length == 4 ? Address[0] == 127 : Address.Slice(0, 15).IndexOfAnyExcept((byte)0) < 0 && Address[15] == 1;

        private static bool IsLinkLocal(ReadOnlySpan<byte> Address) =>
            Address.Length == 4 ? Address[0] == 169 && Address[1] == 254 : Address[0] == 0xFE && (Address[1] & 0xC0) == 0x80;

        // NT gives these addresses a scope below subnet on a loopback interface.
        internal static bool IsBelowSubnetScope(ReadOnlySpan<byte> Address) => IsLoopbackAddress(Address) || IsLinkLocal(Address);
    }
}
