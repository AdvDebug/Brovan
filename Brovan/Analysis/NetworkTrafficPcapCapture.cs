using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Writes captured network traffic to a pcap savefile.
    /// </summary>
    public static class NetworkTrafficPcapCapture
    {
        private const uint PcapMagic = 0xA1B2C3D4;
        private const ushort PcapVersionMajor = 2;
        private const ushort PcapVersionMinor = 4;
        private const uint PcapSnapLength = 0xFFFF;
        private const uint LinkTypeRaw = 101;
        private const int MaxPacketPayload = 1400;

        private static readonly object SyncRoot = new();
        private static readonly Dictionary<string, TcpFlowState> TcpFlows = new(StringComparer.Ordinal);
        private static FileStream? OutputStream;
        private static string? OutputPathValue;
        private static long PacketCountValue;

        private sealed class TcpFlowState
        {
            public string EndpointOne;
            public string EndpointTwo;
            public ulong NextSequenceOne = 1;
            public ulong NextSequenceTwo = 1;
        }

        private readonly struct PacketEndpoints
        {
            public readonly IPEndPoint Source;
            public readonly IPEndPoint Destination;

            public PacketEndpoints(IPEndPoint Source, IPEndPoint Destination)
            {
                this.Source = Source;
                this.Destination = Destination;
            }
        }

        private readonly struct EndpointPairKey : IEquatable<EndpointPairKey>
        {
            public readonly string A;
            public readonly string B;

            public EndpointPairKey(string A, string B)
            {
                this.A = A;
                this.B = B;
            }

            public bool Equals(EndpointPairKey Other)
            {
                return string.Equals(A, Other.A, StringComparison.Ordinal) && string.Equals(B, Other.B, StringComparison.Ordinal);
            }

            public override bool Equals(object Obj)
            {
                return Obj is EndpointPairKey Other && Equals(Other);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(A, B);
            }

            public override string ToString()
            {
                return $"{A}|{B}";
            }
        }

        public static bool IsEnabled
        {
            get
            {
                lock (SyncRoot)
                    return OutputStream != null;
            }
        }

        public static string OutputPath
        {
            get
            {
                lock (SyncRoot)
                    return OutputPathValue;
            }
        }

        public static long PacketCount
        {
            get
            {
                lock (SyncRoot)
                    return PacketCountValue;
            }
        }

        public static bool Enable(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            lock (SyncRoot)
            {
                try
                {
                    DisableLocked();

                    string FullPath = System.IO.Path.GetFullPath(Path);
                    string? DirectoryPath = System.IO.Path.GetDirectoryName(FullPath);
                    if (!string.IsNullOrEmpty(DirectoryPath))
                        Directory.CreateDirectory(DirectoryPath);

                    OutputStream = new FileStream(FullPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                    OutputPathValue = FullPath;
                    PacketCountValue = 0;
                    TcpFlows.Clear();

                    WriteGlobalHeaderLocked();
                    return true;
                }
                catch
                {
                    DisableLocked();
                    return false;
                }
            }
        }

        public static void Disable()
        {
            lock (SyncRoot)
            {
                DisableLocked();
            }
        }

        public static void RecordOutbound(Socket Socket, ReadOnlySpan<byte> Payload, EndPoint? RemoteOverride = null)
        {
            Record(Socket, Payload, true, RemoteOverride);
        }

        public static void RecordInbound(Socket Socket, ReadOnlySpan<byte> Payload, EndPoint? RemoteOverride = null)
        {
            Record(Socket, Payload, false, RemoteOverride);
        }

        private static void Record(Socket Socket, ReadOnlySpan<byte> Payload, bool Outbound, EndPoint? RemoteOverride)
        {
            if (Socket == null || Payload.Length == 0)
                return;

            try
            {
                if (Socket.SocketType == SocketType.Stream || Socket.SocketType == SocketType.Seqpacket)
                {
                    RecordTcp(Socket, Payload, Outbound, RemoteOverride);
                    return;
                }

                if (Socket.SocketType == SocketType.Dgram)
                {
                    RecordUdp(Socket, Payload, Outbound, RemoteOverride);
                    return;
                }
            }
            catch
            {
            }
        }

        private static void RecordUdp(Socket Socket, ReadOnlySpan<byte> Payload, bool Outbound, EndPoint? RemoteOverride)
        {
            if (!TryGetEndpoints(Socket, Outbound, RemoteOverride, out PacketEndpoints Endpoints))
                return;

            lock (SyncRoot)
            {
                if (OutputStream == null)
                    return;

                try
                {
                    WriteIpv4OrIpv6PacketLocked(Endpoints.Source, Endpoints.Destination, ProtocolType.Udp, Payload, 0, 0, 0, 0);
                }
                catch
                {
                    DisableLocked();
                }
            }
        }

        private static void RecordTcp(Socket Socket, ReadOnlySpan<byte> Payload, bool Outbound, EndPoint? RemoteOverride)
        {
            if (!TryGetEndpoints(Socket, Outbound, RemoteOverride, out PacketEndpoints Endpoints))
                return;

            lock (SyncRoot)
            {
                if (OutputStream == null)
                    return;

                string SourceKey = FormatEndpointKey(Endpoints.Source);
                string DestinationKey = FormatEndpointKey(Endpoints.Destination);

                EndpointPairKey PairKey = CreatePairKey(SourceKey, DestinationKey);
                if (!TcpFlows.TryGetValue(PairKey.ToString(), out TcpFlowState State))
                {
                    State = new TcpFlowState
                    {
                        EndpointOne = SourceKey,
                        EndpointTwo = DestinationKey
                    };
                    TcpFlows[PairKey.ToString()] = State;
                }

                bool SourceIsOne = string.Equals(State.EndpointOne, SourceKey, StringComparison.Ordinal);
                ulong Sequence = SourceIsOne ? State.NextSequenceOne : State.NextSequenceTwo;
                ulong Acknowledgment = SourceIsOne ? State.NextSequenceTwo : State.NextSequenceOne;
                ulong InitialSequence = Sequence;

                try
                {
                    const int ChunkSize = MaxPacketPayload;
                    if (Payload.Length <= ChunkSize)
                    {
                        WriteIpv4OrIpv6PacketLocked(Endpoints.Source, Endpoints.Destination, ProtocolType.Tcp, Payload, Sequence, Acknowledgment, 0x18, 0);
                    }
                    else
                    {
                        int Offset = 0;
                        while (Offset < Payload.Length)
                        {
                            int Count = Math.Min(ChunkSize, Payload.Length - Offset);
                            WriteIpv4OrIpv6PacketLocked(Endpoints.Source, Endpoints.Destination, ProtocolType.Tcp, Payload.Slice(Offset, Count), Sequence, Acknowledgment, 0x18, 0);
                            Sequence += (ulong)Count;
                            Offset += Count;
                        }
                    }

                    ulong NextSequence = InitialSequence + (ulong)Payload.Length;
                    if (SourceIsOne)
                        State.NextSequenceOne = NextSequence;
                    else
                        State.NextSequenceTwo = NextSequence;
                }
                catch
                {
                    DisableLocked();
                }
            }
        }

        private static bool TryGetEndpoints(Socket Socket, bool Outbound, EndPoint? RemoteOverride, out PacketEndpoints Endpoints)
        {
            Endpoints = default;

            if (Socket == null)
                return false;

            try
            {
                if (!TryGetIpEndPoint(Socket.LocalEndPoint, out IPEndPoint LocalEndPoint))
                    return false;

                IPEndPoint RemoteEndPoint = null;
                if (!TryGetIpEndPoint(RemoteOverride ?? Socket.RemoteEndPoint, out RemoteEndPoint))
                    return false;

                LocalEndPoint = Normalize(LocalEndPoint);
                RemoteEndPoint = Normalize(RemoteEndPoint);

                Endpoints = Outbound ? new PacketEndpoints(LocalEndPoint, RemoteEndPoint) : new PacketEndpoints(RemoteEndPoint, LocalEndPoint);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryGetIpEndPoint(EndPoint? EndPointValue, out IPEndPoint IpEndPoint)
        {
            IpEndPoint = null;
            if (EndPointValue is not IPEndPoint EndPoint)
                return false;

            IpEndPoint = Normalize(EndPoint);
            return true;
        }

        private static IPEndPoint Normalize(IPEndPoint EndPointValue)
        {
            IPAddress Address = EndPointValue.Address;
            if (Address.IsIPv4MappedToIPv6)
                Address = Address.MapToIPv4();

            return new IPEndPoint(Address, EndPointValue.Port);
        }

        private static EndpointPairKey CreatePairKey(string A, string B)
        {
            return string.CompareOrdinal(A, B) <= 0 ? new EndpointPairKey(A, B) : new EndpointPairKey(B, A);
        }

        private static string FormatEndpointKey(IPEndPoint EndPointValue)
        {
            byte[] AddressBytes = EndPointValue.Address.GetAddressBytes();
            return $"{(int)EndPointValue.AddressFamily}:{Convert.ToHexString(AddressBytes)}:{EndPointValue.Port}";
        }

        private static void WriteGlobalHeaderLocked()
        {
            Span<byte> Header = stackalloc byte[24];

            // Pcap global header layout:
            // 0x00 magic, 0x04 version major, 0x06 version minor, 0x08 timezone offset,
            // 0x0C timestamp accuracy, 0x10 snapshot length, 0x14 link type.
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0, 4), PcapMagic);
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(4, 2), PcapVersionMajor);
            BinaryPrimitives.WriteUInt16LittleEndian(Header.Slice(6, 2), PcapVersionMinor);
            BinaryPrimitives.WriteInt32LittleEndian(Header.Slice(8, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(12, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(16, 4), PcapSnapLength);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(20, 4), LinkTypeRaw);
            OutputStream.Write(Header);
            OutputStream.Flush();
        }

        private static void WriteIpv4OrIpv6PacketLocked(IPEndPoint Source, IPEndPoint Destination, ProtocolType Protocol, ReadOnlySpan<byte> Payload, ulong Sequence, ulong Acknowledgment, byte TcpFlags, byte UdpFlags)
        {
            byte[] Packet = BuildPacket(Source, Destination, Protocol, Payload, Sequence, Acknowledgment, TcpFlags, UdpFlags, out int PacketLength);
            WritePacketRecordLocked(Packet.AsSpan(0, PacketLength));
        }

        private static byte[] BuildPacket(IPEndPoint Source, IPEndPoint Destination, ProtocolType Protocol, ReadOnlySpan<byte> Payload, ulong Sequence, ulong Acknowledgment, byte TcpFlags, byte UdpFlags, out int PacketLength)
        {
            bool IsIpv6 = Source.AddressFamily == AddressFamily.InterNetworkV6 || Destination.AddressFamily == AddressFamily.InterNetworkV6;
            int IpHeaderLength = IsIpv6 ? 40 : 20;
            int TransportHeaderLength = Protocol == ProtocolType.Tcp ? 20 : 8;
            int TotalLength = IpHeaderLength + TransportHeaderLength + Payload.Length;
            byte[] Packet = new byte[TotalLength];

            if (IsIpv6)
                BuildIpv6Packet(Packet, Source, Destination, Protocol, Payload, Sequence, Acknowledgment, TcpFlags, UdpFlags);
            else
                BuildIpv4Packet(Packet, Source, Destination, Protocol, Payload, Sequence, Acknowledgment, TcpFlags, UdpFlags);

            PacketLength = Packet.Length;
            return Packet;
        }

        private static void BuildIpv4Packet(byte[] Packet, IPEndPoint Source, IPEndPoint Destination, ProtocolType Protocol, ReadOnlySpan<byte> Payload, ulong Sequence, ulong Acknowledgment, byte TcpFlags, byte UdpFlags)
        {
            Span<byte> Span = Packet.AsSpan();
            int HeaderLength = 20;
            int TransportLength = Protocol == ProtocolType.Tcp ? 20 : 8;
            int TotalLength = HeaderLength + TransportLength + Payload.Length;

            // IPv4 header offsets:
            // 0x00 version/IHL, 0x01 DSCP/ECN, 0x02 total length, 0x04 identification,
            // 0x06 flags/fragment offset, 0x08 TTL, 0x09 protocol.
            Span[0] = 0x45;
            Span[1] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(Span.Slice(2, 2), (ushort)TotalLength);
            BinaryPrimitives.WriteUInt16BigEndian(Span.Slice(4, 2), (ushort)Environment.TickCount);
            BinaryPrimitives.WriteUInt16BigEndian(Span.Slice(6, 2), 0);
            Span[8] = 64;
            Span[9] = Protocol == ProtocolType.Tcp ? (byte)ProtocolType.Tcp : (byte)ProtocolType.Udp;

            byte[] SourceBytes = Normalize(Source).Address.GetAddressBytes();
            byte[] DestinationBytes = Normalize(Destination).Address.GetAddressBytes();
            SourceBytes.CopyTo(Span.Slice(12, 4));
            DestinationBytes.CopyTo(Span.Slice(16, 4));

            if (Protocol == ProtocolType.Tcp)
                BuildTcpPacket(Span.Slice(HeaderLength), Source, Destination, Payload, Sequence, Acknowledgment, TcpFlags, false);
            else
                BuildUdpPacket(Span.Slice(HeaderLength), Source, Destination, Payload, false);

            BinaryPrimitives.WriteUInt16BigEndian(Span.Slice(10, 2), ComputeChecksum(Span.Slice(0, HeaderLength)));
        }

        private static void BuildIpv6Packet(byte[] Packet, IPEndPoint Source, IPEndPoint Destination, ProtocolType Protocol, ReadOnlySpan<byte> Payload, ulong Sequence, ulong Acknowledgment, byte TcpFlags, byte UdpFlags)
        {
            Span<byte> Span = Packet.AsSpan();
            int HeaderLength = 40;
            int TransportLength = Protocol == ProtocolType.Tcp ? 20 : 8;
            int PayloadLength = TransportLength + Payload.Length;

            BinaryPrimitives.WriteUInt32BigEndian(Span.Slice(0, 4), 0x60000000);
            BinaryPrimitives.WriteUInt16BigEndian(Span.Slice(4, 2), (ushort)PayloadLength);
            Span[6] = Protocol == ProtocolType.Tcp ? (byte)ProtocolType.Tcp : (byte)ProtocolType.Udp;
            Span[7] = 64;

            byte[] SourceBytes = Normalize(Source).Address.GetAddressBytes();
            byte[] DestinationBytes = Normalize(Destination).Address.GetAddressBytes();
            SourceBytes.CopyTo(Span.Slice(8, 16));
            DestinationBytes.CopyTo(Span.Slice(24, 16));

            if (Protocol == ProtocolType.Tcp)
                BuildTcpPacket(Span.Slice(HeaderLength), Source, Destination, Payload, Sequence, Acknowledgment, TcpFlags, true);
            else
                BuildUdpPacket(Span.Slice(HeaderLength), Source, Destination, Payload, true);
        }

        private static void BuildUdpPacket(Span<byte> Transport, IPEndPoint Source, IPEndPoint Destination, ReadOnlySpan<byte> Payload, bool IsIpv6)
        {
            // UDP header offsets:
            // 0x00 source port, 0x02 destination port, 0x04 length, 0x06 checksum.
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(0, 2), (ushort)Source.Port);
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(2, 2), (ushort)Destination.Port);
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(4, 2), (ushort)(8 + Payload.Length));
            Transport[6] = 0;
            Transport[7] = 0;
            Payload.CopyTo(Transport.Slice(8));
            ushort Checksum = ComputeTransportChecksum(Source, Destination, 17, Transport.Slice(0, 8 + Payload.Length), IsIpv6);
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(6, 2), Checksum);
        }

        private static void BuildTcpPacket(Span<byte> Transport, IPEndPoint Source, IPEndPoint Destination, ReadOnlySpan<byte> Payload, ulong Sequence, ulong Acknowledgment, byte Flags, bool IsIpv6)
        {
            // TCP header offsets:
            // 0x00 source port, 0x02 destination port, 0x04 sequence number,
            // 0x08 acknowledgment number, 0x0C data offset/reserved, 0x0D flags,
            // 0x0E window size, 0x10 checksum, 0x12 urgent pointer.
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(0, 2), (ushort)Source.Port);
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(2, 2), (ushort)Destination.Port);
            BinaryPrimitives.WriteUInt32BigEndian(Transport.Slice(4, 4), (uint)Sequence);
            BinaryPrimitives.WriteUInt32BigEndian(Transport.Slice(8, 4), (uint)Acknowledgment);
            Transport[12] = 5 << 4;
            Transport[13] = Flags == 0 ? (byte)0x10 : Flags;
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(14, 2), 65535);
            Transport[16] = 0;
            Transport[17] = 0;
            Transport[18] = 0;
            Transport[19] = 0;
            Payload.CopyTo(Transport.Slice(20));
            ushort Checksum = ComputeTransportChecksum(Source, Destination, 6, Transport.Slice(0, 20 + Payload.Length), IsIpv6);
            BinaryPrimitives.WriteUInt16BigEndian(Transport.Slice(16, 2), Checksum);
        }

        private static ushort ComputeTransportChecksum(IPEndPoint Source, IPEndPoint Destination, byte Protocol, ReadOnlySpan<byte> Segment, bool IsIpv6)
        {
            ulong Sum = 0;

            byte[] SourceBytes = Normalize(Source).Address.GetAddressBytes();
            byte[] DestinationBytes = Normalize(Destination).Address.GetAddressBytes();

            if (IsIpv6)
            {
                Sum = AddBytes(Sum, SourceBytes);
                Sum = AddBytes(Sum, DestinationBytes);

                Span<byte> LengthAndNext = stackalloc byte[8];
                LengthAndNext.Clear();
                BinaryPrimitives.WriteUInt32BigEndian(LengthAndNext.Slice(0, 4), (uint)Segment.Length);
                LengthAndNext[7] = Protocol;
                Sum = AddBytes(Sum, LengthAndNext);
            }
            else
            {
                Sum = AddBytes(Sum, SourceBytes);
                Sum = AddBytes(Sum, DestinationBytes);

                Span<byte> PseudoHeader = stackalloc byte[4];
                PseudoHeader[0] = 0;
                PseudoHeader[1] = Protocol;
                BinaryPrimitives.WriteUInt16BigEndian(PseudoHeader.Slice(2, 2), (ushort)Segment.Length);
                Sum = AddBytes(Sum, PseudoHeader);
            }

            Sum = AddBytes(Sum, Segment);
            while ((Sum >> 16) != 0)
                Sum = (Sum & 0xFFFF) + (Sum >> 16);

            ushort Result = (ushort)~Sum;
            return Result == 0 ? (ushort)0xFFFF : Result;
        }

        private static ulong AddBytes(ulong Sum, ReadOnlySpan<byte> Data)
        {
            int Index = 0;
            while (Index + 1 < Data.Length)
            {
                Sum += (ulong)BinaryPrimitives.ReadUInt16BigEndian(Data.Slice(Index, 2));
                Index += 2;
            }

            if (Index < Data.Length)
                Sum += (ulong)(Data[Index] << 8);

            return Sum;
        }

        private static ushort ComputeChecksum(ReadOnlySpan<byte> Data)
        {
            ulong Sum = AddBytes(0, Data);
            while ((Sum >> 16) != 0)
                Sum = (Sum & 0xFFFF) + (Sum >> 16);

            ushort Result = (ushort)~Sum;
            return Result == 0 ? (ushort)0xFFFF : Result;
        }

        private static void WritePacketRecordLocked(ReadOnlySpan<byte> PacketData)
        {
            if (OutputStream == null)
                return;

            int CapturedLength = Math.Min(PacketData.Length, (int)PcapSnapLength);
            long UnixMilliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            uint TimestampSeconds = (uint)(UnixMilliseconds / 1000);
            uint TimestampMicros = (uint)((UnixMilliseconds % 1000) * 1000);

            Span<byte> Header = stackalloc byte[16];

            // Packet record layout:
            // 0x00 timestamp seconds, 0x04 timestamp microseconds,
            // 0x08 captured length, 0x0C original length.
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0, 4), TimestampSeconds);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(4, 4), TimestampMicros);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(8, 4), (uint)CapturedLength);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(12, 4), (uint)PacketData.Length);

            OutputStream.Write(Header);
            OutputStream.Write(PacketData.Slice(0, CapturedLength));
            OutputStream.Flush();
            PacketCountValue++;
        }

        private static void DisableLocked()
        {
            try
            {
                OutputStream?.Flush();
                OutputStream?.Dispose();
            }
            catch
            {
            }

            OutputStream = null;
            OutputPathValue = null;
            PacketCountValue = 0;
            TcpFlows.Clear();
        }
    }
}
