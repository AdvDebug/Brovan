using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal readonly record struct GuestNetworkAddress(IPAddress Address, byte PrefixLength, uint PrefixOrigin, uint SuffixOrigin)
    {
        // The origins as NL_PREFIX_ORIGIN and NL_SUFFIX_ORIGIN number them.
        internal const uint OriginManual = 1;
        internal const uint OriginWellKnown = 2;

        internal bool IsIPv4 => Address.AddressFamily == AddressFamily.InterNetwork;
    }

    internal sealed class GuestNetworkInterface
    {
        internal const uint TypeEthernet = 6;
        internal const uint TypeSoftwareLoopback = 24;

        internal uint Index { get; init; }
        internal ulong Luid { get; init; }
        internal Guid InterfaceGuid { get; init; }
        internal Guid NetworkGuid { get; init; }
        internal uint Type { get; init; }
        internal string Description { get; init; }
        internal string Alias { get; init; }
        internal byte[] PhysicalAddress { get; init; }
        internal uint Mtu { get; init; }
        internal ulong LinkSpeed { get; init; }
        internal bool Connected { get; init; }
        internal bool Hardware { get; init; }
        internal uint AccessType { get; init; }
        internal uint MediaType { get; init; }
        internal uint PhysicalMediumType { get; init; }
        internal GuestNetworkAddress[] Addresses { get; init; }
        internal IPAddress[] Gateways { get; init; } = Array.Empty<IPAddress>();

        internal bool IsLoopback => Type == TypeSoftwareLoopback;
    }

    internal sealed class GuestNetworkSnapshot
    {
        internal GuestNetworkSnapshot(GuestNetworkInterface[] Interfaces, long CreatedAt)
        {
            this.Interfaces = Interfaces;
            this.CreatedAt = CreatedAt;
        }

        // In ascending NET_LUID order, as NDIS enumerates its interfaces.
        internal GuestNetworkInterface[] Interfaces { get; }

        // A FILETIME of when the addresses were assigned.
        internal long CreatedAt { get; }
    }

    internal sealed class GuestNetworkInterfaces
    {
        private const int RefreshMilliseconds = 5000;

        private static readonly GuestNetworkInterface Loopback = new GuestNetworkInterface
        {
            Index = 1,
            Luid = BuildLuid(GuestNetworkInterface.TypeSoftwareLoopback, 0),
            InterfaceGuid = new Guid("4f8c1a62-7b3e-4d1a-9e55-2b7a0c6d1e01"),
            NetworkGuid = new Guid("4f8c1a62-7b3e-4d1a-9e55-2b7a0c6d1e02"),
            Type = GuestNetworkInterface.TypeSoftwareLoopback,
            Description = "Software Loopback Interface 1",
            Alias = "Loopback Pseudo-Interface 1",
            PhysicalAddress = Array.Empty<byte>(),
            Mtu = 1500,
            LinkSpeed = 1073741824,
            Connected = true,
            AccessType = 1,
            MediaType = 17,
            Addresses = new[]
            {
                new GuestNetworkAddress(IPAddress.Loopback, 8, GuestNetworkAddress.OriginWellKnown, GuestNetworkAddress.OriginWellKnown),
                new GuestNetworkAddress(IPAddress.IPv6Loopback, 128, GuestNetworkAddress.OriginWellKnown, GuestNetworkAddress.OriginWellKnown),
            },
        };

        private readonly Action Wake;
        private readonly bool HasAdapter;
        private readonly long CreatedAt;
        private GuestNetworkSnapshot Current;
        private GuestNetworkSnapshot Disconnected;
        private Task<HostAddresses> Probe;
        private bool ReportedFailure;
        private bool ReportedTruncation;
        private long ProbedAt;
        private int Ended;

        internal GuestNetworkInterfaces(NetworkAccessPolicy Policy, long CreatedAt, Action Wake)
        {
            this.Wake = Wake;
            this.CreatedAt = CreatedAt;
            HasAdapter = Policy.ReachesBeyondLoopback();
            if (!HasAdapter)
                Current = new GuestNetworkSnapshot(new[] { Loopback }, CreatedAt);
        }

        /// <returns>The current snapshot, or null with the host work to wait for when the first probe still runs.</returns>
        internal GuestNetworkSnapshot TryGetSnapshot(out Task Pending)
        {
            Pending = null;
            if (!HasAdapter)
                return Current;

            if (Probe is { IsCompleted: true } Done)
            {
                Probe = null;
                Publish(Done.Result);
            }

            if (Probe == null && (Current == null || Environment.TickCount64 - ProbedAt >= RefreshMilliseconds))
                StartProbe();

            if (Current == null)
                Pending = Probe;

            return Current;
        }

        // The adapter shows no connection, for a caller that cannot wait for the first probe.
        internal GuestNetworkSnapshot WithoutHostAddresses() =>
            Disconnected ??= new GuestNetworkSnapshot(new[] { BuildAdapter(Array.Empty<GuestNetworkAddress>(), Array.Empty<IPAddress>()), Loopback }, CreatedAt);

        internal void End()
        {
            Volatile.Write(ref Ended, 1);
        }

        private void StartProbe()
        {
            ProbedAt = Environment.TickCount64;
            Task<HostAddresses> Started = Task.Run(ReadHostAddresses);
            Probe = Started;
            Started.ContinueWith(_ =>
            {
                if (Volatile.Read(ref Ended) == 0)
                    Wake();
            }, TaskContinuationOptions.ExecuteSynchronously);
        }

        private void Publish(HostAddresses Read)
        {
            if (Read.Failure != null && !ReportedFailure)
                Utils.LogError($"[GuestNetworkInterfaces] The host addresses could not be read: {Read.Failure}");
            if (Read.Truncated && !ReportedTruncation)
                Utils.LogError($"[GuestNetworkInterfaces] The host has more than {MemoryBudget.GuestNetworkAddresses} addresses; the guest adapter reports the first ones.");

            ReportedFailure = Read.Failure != null;
            ReportedTruncation = Read.Truncated;
            Current = new GuestNetworkSnapshot(new[] { BuildAdapter(Read.Addresses, Read.Gateways), Loopback }, CreatedAt);
        }

        private readonly record struct HostAddresses(GuestNetworkAddress[] Addresses, IPAddress[] Gateways, bool Truncated, string Failure);

        private static GuestNetworkInterface BuildAdapter(GuestNetworkAddress[] Addresses, IPAddress[] Gateways)
        {
            return new GuestNetworkInterface
            {
                Index = 2,
                Luid = BuildLuid(GuestNetworkInterface.TypeEthernet, 1),
                InterfaceGuid = new Guid("4f8c1a62-7b3e-4d1a-9e55-2b7a0c6d1e11"),
                NetworkGuid = new Guid("4f8c1a62-7b3e-4d1a-9e55-2b7a0c6d1e12"),
                Type = GuestNetworkInterface.TypeEthernet,
                Description = "Brovan Virtual Ethernet Adapter",
                Alias = "Ethernet",
                PhysicalAddress = new byte[] { 0x02, 0x42, 0x52, 0x56, 0x00, 0x01 },
                Mtu = 1500,
                LinkSpeed = 1000000000,
                Connected = Addresses.Length != 0,
                Hardware = true,
                AccessType = 2,
                PhysicalMediumType = 14,
                Addresses = Addresses,
                Gateways = Addresses.Length != 0 ? Gateways : Array.Empty<IPAddress>(),
            };
        }

        private static ulong BuildLuid(uint Type, uint NetLuidIndex) => ((ulong)Type << 48) | ((ulong)NetLuidIndex << 24);

        private static HostAddresses ReadHostAddresses()
        {
            List<GuestNetworkAddress> Found = new List<GuestNetworkAddress>();
            List<IPAddress> Gateways = new List<IPAddress>();
            try
            {
                foreach (NetworkInterface Host in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (Host.OperationalStatus != OperationalStatus.Up || Host.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                        continue;

                    IPInterfaceProperties Properties = Host.GetIPProperties();
                    foreach (UnicastIPAddressInformation Unicast in Properties.UnicastAddresses)
                    {
                        if (!IsReportable(Unicast.Address) || Contains(Found, Unicast.Address))
                            continue;

                        if (Found.Count == MemoryBudget.GuestNetworkAddresses)
                            return new HostAddresses(Found.ToArray(), Gateways.ToArray(), true, null);

                        Found.Add(ToGuestAddress(Unicast));
                    }

                    AddGateways(Properties, Gateways);
                }
            }
            catch (Exception Error)
            {
                return new HostAddresses(Array.Empty<GuestNetworkAddress>(), Array.Empty<IPAddress>(), false, Error.Message);
            }

            return new HostAddresses(Found.ToArray(), Gateways.ToArray(), false, null);
        }

        private static bool IsReportable(IPAddress Address)
        {
            if (IPAddress.IsLoopback(Address))
                return false;

            if (Address.AddressFamily == AddressFamily.InterNetwork)
                return true;

            if (Address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            Span<byte> Bytes = stackalloc byte[16];
            Address.TryWriteBytes(Bytes, out _);

            // An EUI-64 interface identifier carries the host adapter's MAC address.
            return !(Bytes[11] == 0xFF && Bytes[12] == 0xFE);
        }

        private static GuestNetworkAddress ToGuestAddress(UnicastIPAddressInformation Unicast)
        {
            uint PrefixOrigin = GuestNetworkAddress.OriginManual;
            uint SuffixOrigin = GuestNetworkAddress.OriginManual;
            if (OperatingSystem.IsWindows())
            {
                PrefixOrigin = (uint)Unicast.PrefixOrigin;
                SuffixOrigin = (uint)Unicast.SuffixOrigin;
            }

            return new GuestNetworkAddress(WithoutScope(Unicast.Address), (byte)Unicast.PrefixLength, PrefixOrigin, SuffixOrigin);
        }

        // A host that cannot give its gateways still gives its addresses; the guest then has no default route.
        private static void AddGateways(IPInterfaceProperties Properties, List<IPAddress> Gateways)
        {
            GatewayIPAddressInformationCollection Found;
            try
            {
                Found = Properties.GatewayAddresses;
            }
            catch (Exception Error) when (Error is NetworkInformationException or PlatformNotSupportedException)
            {
                return;
            }

            foreach (GatewayIPAddressInformation Gateway in Found)
            {
                IPAddress Address = WithoutScope(Gateway.Address);
                if (IsReportable(Address) && !Address.Equals(IPAddress.Any) && !Address.Equals(IPAddress.IPv6Any) && !Gateways.Contains(Address)
                    && Gateways.Count < MemoryBudget.GuestNetworkAddresses)
                    Gateways.Add(Address);
            }
        }

        private static IPAddress WithoutScope(IPAddress Address) =>
            Address.AddressFamily == AddressFamily.InterNetworkV6 && Address.ScopeId != 0 ? new IPAddress(Address.GetAddressBytes()) : Address;

        private static bool Contains(List<GuestNetworkAddress> Found, IPAddress Address)
        {
            foreach (GuestNetworkAddress Existing in Found)
            {
                if (Existing.Address.Equals(Address))
                    return true;
            }

            return false;
        }
    }
}
