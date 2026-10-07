using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Brovan.Core.Emulation;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class AfdDevice : IDisposable
    {
        private const int FsctlAfdBase = 0x12;

        private const int AFD_BIND = 0;
        private const int AFD_CONNECT = 1;
        private const int AFD_START_LISTEN = 2;
        private const int AFD_WAIT_FOR_LISTEN = 3;
        private const int AFD_ACCEPT = 4;
        private const int AFD_RECEIVE = 5;
        private const int AFD_RECEIVE_DATAGRAM = 6;
        private const int AFD_SEND = 7;
        private const int AFD_SEND_DATAGRAM = 8;
        private const int AFD_POLL = 9;
        private const int AFD_PARTIAL_DISCONNECT = 10;
        private const int AFD_GET_ADDRESS = 11;
        private const int AFD_QUERY_HANDLES = 13;
        private const int AFD_SET_INFO = 14;
        private const int AFD_GET_REMOTE_ADDRESS = 15;
        private const int AFD_GET_CONTEXT = 16;
        private const int AFD_SET_CONTEXT = 17;
        private const int AFD_GET_INFORMATION = 30;
        private const int AFD_SUPER_ACCEPT = 32;
        private const int AFD_EVENT_SELECT = 33;
        private const int AFD_ENUM_NETWORK_EVENTS = 34;
        private const int AFD_ROUTING_INTERFACE_QUERY = 42;
        private const int AFD_ADDRESS_LIST_QUERY = 44;
        private const int AFD_TRANSPORT_IOCTL = 47;
        private const int AFD_SUPER_CONNECT = 49;

        private const uint MethodNeither = 3;
        private const uint IoctlAfdConnect = ((uint)FsctlAfdBase << 12) | ((uint)AFD_CONNECT << 2) | MethodNeither;

        private const int TransportLevelOffset = 4;
        private const int TransportIoctlCodeOffset = 8;
        private const int TransportBufferOffset = 0x10;
        private const uint TransportSetOption = 1;
        private const uint TransportGetOption = 2;
        private const uint IocInOut = 0xC0000000;
        private const uint IocWs2 = 0x08000000;
        private const uint SioAddressListSort = IocInOut | IocWs2 | 25;
        private const uint IpProtoIpv6 = 41;
        private const uint Ipv6V6Only = 27;

        private const uint SuperConnectMinInput = 0xC;
        private const int SuperConnectAddressOffset = 10;

        private const uint AFD_POLL_RECEIVE = 1u << 0;
        private const uint AFD_POLL_SEND = 1u << 2;
        private const uint AFD_POLL_DISCONNECT = 1u << 3;
        private const uint AFD_POLL_ABORT = 1u << 4;
        private const uint AFD_POLL_LOCAL_CLOSE = 1u << 5;
        private const uint AFD_POLL_CONNECT = 1u << 6;
        private const uint AFD_POLL_ACCEPT = 1u << 7;
        private const uint AFD_POLL_CONNECT_FAIL = 1u << 8;

        // AFD_POLL_INFO
        private const int PollHeaderSize = 16;
        private const int PollCountOffset = 8;
        private const int PollExclusiveOffset = 12;
        private const uint MaxPollHandles = 0x6666661;

        private const uint PollReadEvents = AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT;
        private const uint PollWriteEvents = AFD_POLL_SEND | AFD_POLL_CONNECT;
        // AFD raises LOCAL_CLOSE only on the last handle close.
        private const uint PollErrorEvents = AFD_POLL_CONNECT_FAIL | AFD_POLL_ABORT;

        private const uint AFD_INFO_BLOCKING_MODE = 2;
        private const uint AFD_INFO_MAX_SEND_SIZE = 3;
        private const uint AFD_INFO_SENDS_PENDING = 4;
        private const uint AFD_INFO_MAX_PATH_SEND_SIZE = 5;
        private const uint AFD_INFO_RECEIVE_WINDOW_SIZE = 6;
        private const uint AFD_INFO_SEND_WINDOW_SIZE = 7;
        private const uint AFD_INFO_CONNECT_TIME = 8;
        private const uint AFD_INFO_GROUP_ID_AND_TYPE = 10;
        private const uint AFD_INFO_DELIVERY_STATUS = 14;
        private const uint AfdInfoSize = 0x10;
        private const uint MaxDatagramBytesV4 = 65507;
        private const uint MaxDatagramBytesV6 = 65527;

        private const uint MaxContextBytes = 0x10000;
        private const uint AFD_OVERLAPPED = 0x2;

        private const uint AFD_DISCONNECT_SEND = 0x1;
        private const uint AFD_DISCONNECT_RECV = 0x2;
        private const uint AfdDisconnectInfoSize = 0x10;

        private const int PollRetrySliceMs = 1;

        private BrovanSocket? _socket;
        private NetworkAccessPolicy _policy;
        private bool IsListening;
        private bool _nonBlocking;
        private bool _connectPending;
        private NTSTATUS _connectFailure;
        private bool _v6Only = true;

        private bool _superAcceptTarget;
        private byte[]? _context;
        private long _connectedAt;

        private readonly Dictionary<int, BrovanSocket> _PendingAccepted = new();
        private int _NextSequence;

        private int WinAf = 2;
        private int WinType = 1;
        private int WinProtocol = 6;

        public AfdDevice(byte[]? EaBuffer = null)
        {
            if (EaBuffer != null && EaBuffer.Length > 0)
                TryParseCreationData(EaBuffer);
        }

        public void Dispose()
        {
            try { _socket?.Dispose(); } catch { }
            _socket = null;
            _PendingAccepted.Clear();
        }

        // Dispose blocks while the watcher's Select holds the socket.
        private void ReleaseSocket(BinaryEmulator Instance)
        {
            BrovanSocket? Released = _socket;
            _socket = null;
            _connectedAt = 0;
            if (Released != null)
                Instance.WinHelper.AfdRequests.ReleaseSocket(this, Released);
        }

        private static int DecodeRequest(uint Ioctl) => (int)((Ioctl >> 2) & 0x03FF);

        // NT: AfdIoctlTable, the transfer method of each request.
        private static ReadOnlySpan<byte> AfdRequestMethods => new byte[]
        {
            3, 3, 3, 0, 0, 3, 3, 3, 3, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0,
            0, 0, 3, 0, 3, 3, 0, 3, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 3, 3, 3, 3, 3, 3
        };

        private static bool IsAfdRequest(uint Ioctl)
        {
            int Request = DecodeRequest(Ioctl);
            return Request < AfdRequestMethods.Length && Ioctl == (((uint)FsctlAfdBase << 12) | ((uint)Request << 2) | AfdRequestMethods[Request]);
        }

        private static ushort Swap16(ushort Value) => (ushort)(((Value & 0x00FF) << 8) | ((Value & 0xFF00) >> 8));

        private static AddressFamily TranslateWinAf(int WinAf)
        {
            return WinAf switch
            {
                2 => AddressFamily.InterNetwork,
                23 => AddressFamily.InterNetworkV6,
                _ => AddressFamily.Unspecified
            };
        }

        // A raw socket has no endpoint the policy can hold it to.
        private static SocketType TranslateWinType(int WinType)
        {
            return WinType switch
            {
                1 => SocketType.Stream,
                2 => SocketType.Dgram,
                _ => SocketType.Unknown
            };
        }

        private static ProtocolType TranslateWinProtocol(int WinProtocol)
        {
            return WinProtocol switch
            {
                6 => ProtocolType.Tcp,
                17 => ProtocolType.Udp,
                _ => ProtocolType.Unspecified
            };
        }

        private static bool IsSupportedSocketShape(SocketType Type, ProtocolType Protocol)
        {
            return Type switch
            {
                SocketType.Stream => Protocol is ProtocolType.Tcp or ProtocolType.Unspecified,
                SocketType.Dgram => Protocol is ProtocolType.Udp or ProtocolType.Unspecified,
                _ => false
            };
        }

        private void EnsureSocket()
        {
            if (_socket != null)
                return;

            AddressFamily Family = TranslateWinAf(WinAf);
            SocketType Type = TranslateWinType(WinType);
            ProtocolType Protocol = TranslateWinProtocol(WinProtocol);

            if (Family == AddressFamily.Unspecified)
                Family = AddressFamily.InterNetwork;

            if (Type == SocketType.Unknown && WinType == 0)
                Type = SocketType.Stream;

            if (!IsSupportedSocketShape(Type, Protocol))
                throw new NotSupportedException("The requested socket type is not available to the guest.");

            // A handler runs under the kernel lock, so no host socket call may wait.
            _socket = new BrovanSocket(Family, Type, Protocol, _policy) { Blocking = false };

            // Linux hosts default to dual-mode sockets, NT to V6-only.
            if (Family == AddressFamily.InterNetworkV6)
                _socket.DualMode = !_v6Only;

            if (Protocol == ProtocolType.Tcp)
            {
                try { _socket.NoDelay = true; } catch { }
            }
        }

        private void TryParseCreationData(byte[] Ea)
        {
            try
            {
                if (Ea.Length < 0x2C)
                    return;

                WinAf = BitConverter.ToInt32(Ea, 0x20);
                WinType = BitConverter.ToInt32(Ea, 0x24);
                WinProtocol = BitConverter.ToInt32(Ea, 0x28);
            }
            catch
            {
            }
        }

        // InputBuffer can be pooled, so only Length bounds the guest data.
        private static IPEndPoint? ParseSockaddr(byte[] Data, uint Length, int Offset)
        {
            uint Available = Math.Min(Length, (uint)Data.Length);
            if (Offset < 0 || Available < (uint)Offset + 4)
                return null;

            short Family = BitConverter.ToInt16(Data, Offset + 0);

            if (Family == 2)
            {
                if (Available < (uint)Offset + 16)
                    return null;

                ushort PortNetwork = BitConverter.ToUInt16(Data, Offset + 2);
                ushort Port = Swap16(PortNetwork);

                return new IPEndPoint(new IPAddress(Data.AsSpan(Offset + 4, 4)), Port);
            }

            if (Family == 23)
            {
                if (Available < (uint)Offset + 28)
                    return null;

                ushort PortNetwork = BitConverter.ToUInt16(Data, Offset + 2);
                ushort Port = Swap16(PortNetwork);

                return new IPEndPoint(new IPAddress(Data.AsSpan(Offset + 8, 16)), Port);
            }

            return null;
        }

        private static byte[] BuildSockaddr(IPEndPoint EndPoint)
        {
            if (EndPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] BufferData = new byte[16];
                BinaryPrimitives.WriteInt16LittleEndian(BufferData.AsSpan(0, 2), 2);

                ushort Port = (ushort)EndPoint.Port;
                BufferData[2] = (byte)((Port >> 8) & 0xFF);
                BufferData[3] = (byte)(Port & 0xFF);

                EndPoint.Address.TryWriteBytes(BufferData.AsSpan(4, 4), out _);
                return BufferData;
            }

            if (EndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] BufferData = new byte[28];
                BinaryPrimitives.WriteInt16LittleEndian(BufferData.AsSpan(0, 2), 23);

                ushort Port = (ushort)EndPoint.Port;
                BufferData[2] = (byte)((Port >> 8) & 0xFF);
                BufferData[3] = (byte)(Port & 0xFF);

                EndPoint.Address.TryWriteBytes(BufferData.AsSpan(8, 16), out _);

                if (EndPoint.Address.ScopeId != 0)
                    BinaryPrimitives.WriteUInt32LittleEndian(BufferData.AsSpan(24, 4), (uint)EndPoint.Address.ScopeId);

                return BufferData;
            }

            return Array.Empty<byte>();
        }

        private static ulong ReadPtr(BinaryEmulator Emulator, byte[] Data, int Offset)
        {
            if (Emulator._binary.Architecture == BinaryArchitecture.x64)
                return BitConverter.ToUInt64(Data, Offset);

            return BitConverter.ToUInt32(Data, Offset);
        }

        private static uint ReadU32(byte[] Data, int Offset)
        {
            if (Data.Length < Offset + 4)
                return 0;

            return BitConverter.ToUInt32(Data, Offset);
        }

        private static uint GuestInputLength(in DeviceData Data) =>
            Data.InputBuffer == null ? 0u : Math.Min(Data.InputLength, (uint)Data.InputBuffer.Length);

        private static uint GuestOutputLength(in DeviceData Data) =>
            Data.OutputBuffer == null ? 0u : Math.Min(Data.OutputLength, (uint)Data.OutputBuffer.Length);

        private BrovanSocket? TryAccept(out EndPoint? Remote)
        {
            Remote = null;
            EnsureSocket();
            if (_socket == null)
                return null;

            try
            {
                if (!_socket.Poll(0, SelectMode.SelectRead))
                    return null;

                BrovanSocket Accepted = _socket.Accept();
                Remote = Accepted.RemoteEndPoint;
                return Accepted;
            }
            catch
            {
                return null;
            }
        }

        private static uint MapPollEventsToTriggered(uint Requested, bool ReadReady, bool WriteReady, bool ErrorReady, bool IsListening)
        {
            uint Triggered = 0;

            if (ReadReady)
            {
                if (!IsListening && (Requested & AFD_POLL_RECEIVE) != 0)
                    Triggered |= AFD_POLL_RECEIVE;

                if (IsListening && (Requested & AFD_POLL_ACCEPT) != 0)
                    Triggered |= AFD_POLL_ACCEPT;

                if ((Requested & AFD_POLL_DISCONNECT) != 0)
                    Triggered |= AFD_POLL_DISCONNECT;
            }

            if (WriteReady)
            {
                if ((Requested & AFD_POLL_SEND) != 0)
                    Triggered |= AFD_POLL_SEND;

                if ((Requested & AFD_POLL_CONNECT) != 0)
                    Triggered |= AFD_POLL_CONNECT;
            }

            if (ErrorReady)
            {
                if ((Requested & AFD_POLL_CONNECT_FAIL) != 0)
                    Triggered |= AFD_POLL_CONNECT_FAIL;

                if ((Requested & AFD_POLL_ABORT) != 0)
                    Triggered |= AFD_POLL_ABORT;
            }

            return Triggered;
        }

        private static bool IsEndpointAllowed(BinaryEmulator Instance, EndPoint EndPointValue)
        {
            return Instance.Settings.GetNetworkPolicy().IsEndpointAllowed(EndPointValue);
        }

        private static bool IsSocketRemoteAllowed(BinaryEmulator Instance, BrovanSocket Socket, bool RequireKnownRemote)
        {
            NetworkAccessPolicy Policy = Instance.Settings.GetNetworkPolicy();
            if (!Policy.HasAnyAccess())
                return false;

            EndPoint? RemoteEndPoint = null;
            try
            {
                RemoteEndPoint = Socket.RemoteEndPoint;
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
                return false;
            }

            if (RemoteEndPoint != null)
                return Policy.IsEndpointAllowed(RemoteEndPoint);

            return !RequireKnownRemote || Policy.Mode == NetworkAccessMode.Full;
        }

        private NTSTATUS IoctlBind(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            uint InputLength = GuestInputLength(in Data);
            if (Data.InputBuffer == null || InputLength < 4 + 16)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            IPEndPoint? IpEndPoint = ParseSockaddr(Data.InputBuffer, InputLength, 4);
            if (IpEndPoint == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.Settings.GetNetworkPolicy().IsLocalBindAllowed(IpEndPoint))
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            try
            {
                _socket.Bind(IpEndPoint);
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        // AFD ignores ConnectEndpoint on the endpoint itself.
        private NTSTATUS IoctlConnect(ref DeviceData Data, BinaryEmulator Instance)
        {
            NTSTATUS Status = CheckConnectLengths(in Data, Instance);
            return Status == NTSTATUS.STATUS_SUCCESS ? StartConnect(this, ref Data, Instance) : Status;
        }

        private NTSTATUS IoctlListen(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (!Instance.Settings.GetNetworkPolicy().HasAnyAccess())
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            if (Instance.Settings.GetNetworkPolicy().Mode != NetworkAccessMode.Full)
            {
                if (_socket.LocalEndPoint is not IPEndPoint LocalEndPoint || !IsEndpointAllowed(Instance, LocalEndPoint))
                    return NTSTATUS.STATUS_NETWORK_UNREACHABLE;
            }

            if (Data.InputBuffer == null || GuestInputLength(in Data) < 8)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            int Backlog = (int)ReadU32(Data.InputBuffer, 4);
            if (Backlog <= 0)
                Backlog = 16;

            try
            {
                _socket.Listen(Backlog);
            }
            catch
            {
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            IsListening = true;
            Instance.WinHelper.AfdRequests.Recheck(Instance, this);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlWaitForListen(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (!Instance.Settings.GetNetworkPolicy().HasAnyAccess())
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            uint OutputLength = GuestOutputLength(in Data);
            if (Data.OutputBuffer == null || OutputLength < 12)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (OutputLength < 20)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            BrovanSocket? Accepted = TryAccept(out EndPoint? Remote);
            if (Accepted == null)
            {
                if (Instance.WinHelper.TryContinuePipeWait(Data.FileHandle, int.MaxValue, PollRetrySliceMs))
                    return NTSTATUS.STATUS_PENDING;

                // STATUS_TIMEOUT is a success status.
                return NTSTATUS.STATUS_IO_TIMEOUT;
            }

            Instance.WinHelper.ClearPipeWait();

            if (Remote != null && !IsEndpointAllowed(Instance, Remote))
            {
                try { Accepted.Dispose(); } catch { }
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;
            }

            int Sequence = _NextSequence++;
            _PendingAccepted[Sequence] = Accepted;

            Array.Clear(Data.OutputBuffer, 0, (int)OutputLength);
            BinaryPrimitives.WriteInt32LittleEndian(Data.OutputBuffer.AsSpan(0, 4), Sequence);

            uint AddressLength = 16;
            if (Remote is IPEndPoint RemoteIp)
            {
                byte[] SockAddr = BuildSockaddr(RemoteIp);
                AddressLength = Math.Min((uint)SockAddr.Length, OutputLength - 4);
                Buffer.BlockCopy(SockAddr, 0, Data.OutputBuffer, 4, (int)AddressLength);
            }

            Data.Information = 4 + AddressLength;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlAccept(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (Data.InputBuffer == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int MinSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 16 : 12;
            if (GuestInputLength(in Data) < MinSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            int Sequence = BitConverter.ToInt32(Data.InputBuffer, 4);
            ulong AcceptHandle = ReadPtr(Instance, Data.InputBuffer, 8);

            if (!_PendingAccepted.TryGetValue(Sequence, out BrovanSocket Accepted))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinFile? AcceptFile = Instance.WinHelper.GetFileByHandle(AcceptHandle, AccessMask.GiveTemp);
            if (AcceptFile == null || AcceptFile.Handler == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (AcceptFile.Handler.Target is not AfdDevice TargetEndpoint)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            _PendingAccepted.Remove(Sequence);
            TargetEndpoint.Adopt(Instance, Accepted);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private void Adopt(BinaryEmulator Instance, BrovanSocket Accepted)
        {
            Accepted.Blocking = false;
            ReleaseSocket(Instance);
            _socket = Accepted;
            IsListening = false;
            _connectedAt = Instance.GetEmulatedSystemTimeFileTimeUtc();
            Instance.WinHelper.AfdRequests.Recheck(Instance, this);
        }

        // AFD_SUPER_ACCEPT_INFO: SanActive, FixAddressAlignment, accept handle, then receive, local and remote lengths.
        // Output: received data, then the local and remote address areas.
        private NTSTATUS IoctlSuperAccept(ref DeviceData Data, BinaryEmulator Instance)
        {
            int PointerSize = Instance.WinHelper.PointerSize;
            int LengthsOffset = 2 * PointerSize;
            if (Data.InputBuffer == null || GuestInputLength(in Data) < LengthsOffset + 12)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool FixAddressAlignment = Data.InputBuffer[1] != 0;
            ulong AcceptHandle = ReadPtr(Instance, Data.InputBuffer, PointerSize);
            uint ReceiveLength = ReadU32(Data.InputBuffer, LengthsOffset);
            uint LocalLength = ReadU32(Data.InputBuffer, LengthsOffset + 4);
            uint RemoteLength = ReadU32(Data.InputBuffer, LengthsOffset + 8);
            uint OutputLength = Data.OutputLength;

            if (!IsListening || RemoteLength < 8 || LocalLength == 1 || OutputLength < ReceiveLength ||
                OutputLength - ReceiveLength < LocalLength || OutputLength - ReceiveLength - LocalLength < RemoteLength)
                return IsListening ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Data.UserBuffer == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile? AcceptFile = Instance.WinHelper.GetFileByHandle(AcceptHandle, AccessMask.GiveTemp);
            if (AcceptFile?.Handler?.Target is not AfdDevice Target)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Target._superAcceptTarget || ReferenceEquals(Target, this) || Target.IsListening || Target._connectPending ||
                Target.WinType != WinType || (Target._socket != null && (Target._socket.IsBound || Target._socket.Connected)))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Target._superAcceptTarget = true;
            Data.Information = 0;
            return Instance.WinHelper.AfdRequests.Pend(Instance, new PendingAccept(Instance, in Data, this, Target, FixAddressAlignment, ReceiveLength, LocalLength, RemoteLength));
        }

        // TRANSPORT_ADDRESS: the address count and AddressLength, then the sockaddr from its family field on.
        private const int TransportAddressHeaderBytes = 6;

        private int RemoteTdiAddressBytes() => TransportAddressHeaderBytes + (_socket?.AddressFamily == AddressFamily.InterNetworkV6 ? 28 : 16);

        private bool TryTakeConnection(BinaryEmulator Instance, PendingAccept Accept, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;
            BrovanSocket? Socket = _socket;
            if (Socket == null)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return true;
            }

            try
            {
                if (!Socket.Poll(0, SelectMode.SelectRead))
                    return false;
            }
            catch (Exception Ex)
            {
                Utils.LogError($"AFD accept failed on the host: {Ex.Message}");
                Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                return true;
            }

            // NT: the connection stays queued.
            if (Accept.RemoteLength < RemoteTdiAddressBytes())
            {
                Status = NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                return true;
            }

            BrovanSocket? Accepted = TryAccept(out EndPoint? Remote);
            if (Accepted == null)
                return false;

            if (Remote is not IPEndPoint RemoteIp || !IsEndpointAllowed(Instance, RemoteIp) || Accepted.LocalEndPoint is not IPEndPoint LocalIp)
            {
                try { Accepted.Dispose(); } catch { }
                Status = NTSTATUS.STATUS_NETWORK_UNREACHABLE;
                return true;
            }

            if (!WriteAcceptAddresses(Instance, Accept, LocalIp, RemoteIp))
            {
                try { Accepted.Dispose(); } catch { }
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                return true;
            }

            Accept.Target.Adopt(Instance, Accepted);
            return true;
        }

        // Local area: TDI_ADDRESS_INFO. Remote area: TRANSPORT_ADDRESS. FixAddressAlignment puts each sockaddr at the
        // start of its area with its length in the last two bytes, the local one sized less the 10 byte TDI header.
        private static bool WriteAcceptAddresses(BinaryEmulator Instance, PendingAccept Accept, IPEndPoint Local, IPEndPoint Remote)
        {
            const int TdiAddressInfoHeaderBytes = 4 + TransportAddressHeaderBytes;

            ulong LocalArea = Accept.Output + Accept.ReceiveLength;
            ulong RemoteArea = LocalArea + Accept.LocalLength;
            byte[] LocalAddress = BuildSockaddr(Local);
            byte[] RemoteAddress = BuildSockaddr(Remote);
            Span<byte> Area = stackalloc byte[TdiAddressInfoHeaderBytes + 28];

            if (Accept.FixAddressAlignment)
            {
                if (Accept.LocalLength != 0)
                {
                    int Copied = (int)Math.Min((uint)LocalAddress.Length, Accept.LocalLength > TdiAddressInfoHeaderBytes ? Accept.LocalLength - TdiAddressInfoHeaderBytes : 0);
                    BinaryPrimitives.WriteUInt16LittleEndian(Area, (ushort)Copied);
                    if ((Copied != 0 && !Instance.WriteMemory(LocalArea, LocalAddress.AsSpan(0, Copied))) ||
                        !Instance.WriteMemory(LocalArea + Accept.LocalLength - 2, Area.Slice(0, 2)))
                        return false;
                }

                BinaryPrimitives.WriteUInt16LittleEndian(Area, (ushort)RemoteAddress.Length);
                return Instance.WriteMemory(RemoteArea, RemoteAddress) && Instance.WriteMemory(RemoteArea + Accept.RemoteLength - 2, Area.Slice(0, 2));
            }

            if (Accept.LocalLength != 0)
            {
                int Length = WriteTransportAddress(Area.Slice(4), LocalAddress) + 4;
                BinaryPrimitives.WriteUInt32LittleEndian(Area, 0);
                if (!Instance.WriteMemory(LocalArea, Area.Slice(0, (int)Math.Min((uint)Length, Accept.LocalLength))))
                    return false;
            }

            return Instance.WriteMemory(RemoteArea, Area.Slice(0, WriteTransportAddress(Area, RemoteAddress)));
        }

        private static int WriteTransportAddress(Span<byte> Into, byte[] SockAddr)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Into, 1);
            BinaryPrimitives.WriteUInt16LittleEndian(Into.Slice(4), (ushort)(SockAddr.Length - 2));
            SockAddr.CopyTo(Into.Slice(TransportAddressHeaderBytes));
            return TransportAddressHeaderBytes + SockAddr.Length;
        }

        // One buffer needs no array.
        internal readonly struct TransferBuffers
        {
            private readonly ulong FirstAddress;
            private readonly (ulong Address, uint Length)[]? Segments;
            private readonly int Count;
            internal readonly uint Total;

            internal TransferBuffers(ulong Address, uint Length)
            {
                FirstAddress = Address;
                Segments = null;
                Count = 0;
                Total = Length;
            }

            internal TransferBuffers((ulong Address, uint Length)[] Segments, int Count, uint Total)
            {
                FirstAddress = 0;
                this.Segments = Segments;
                this.Count = Count;
                this.Total = Total;
            }

            internal void Release()
            {
                if (Segments != null)
                    ArrayPool<(ulong Address, uint Length)>.Shared.Return(Segments);
            }

            internal bool Read(BinaryEmulator Instance, uint Offset, Span<byte> Into)
            {
                if (Segments == null)
                    return Instance._emulator.ReadMemory(FirstAddress + Offset, Into, (uint)Into.Length);

                int Done = 0;
                for (int i = 0; i < Count && Done < Into.Length; i++)
                {
                    (ulong Address, uint Length) = Segments[i];
                    if (Offset >= Length)
                    {
                        Offset -= Length;
                        continue;
                    }

                    int Take = (int)Math.Min(Length - Offset, (uint)(Into.Length - Done));
                    if (!Instance._emulator.ReadMemory(Address + Offset, Into.Slice(Done, Take), (uint)Take))
                        return false;

                    Done += Take;
                    Offset = 0;
                }

                return Done == Into.Length;
            }

            internal bool Write(BinaryEmulator Instance, ReadOnlySpan<byte> From)
            {
                if (Segments == null)
                    return Instance.WriteMemory(FirstAddress, From);

                int Done = 0;
                for (int i = 0; i < Count && Done < From.Length; i++)
                {
                    (ulong Address, uint Length) = Segments[i];
                    int Take = (int)Math.Min(Length, (uint)(From.Length - Done));
                    if (Take != 0 && !Instance.WriteMemory(Address, From.Slice(Done, Take)))
                        return false;

                    Done += Take;
                }

                return Done == From.Length;
            }
        }

        private const uint MaxTransferBuffers = 1024;

        // AFD_RECV_INFO and AFD_SEND_INFO: WSABUF array, count, AFD flags, TDI flags.
        private static NTSTATUS ReadTransferInfo(in DeviceData Data, BinaryEmulator Instance, out TransferBuffers Buffers, out uint AfdFlags)
        {
            Buffers = default;
            AfdFlags = 0;

            if (Data.InputBuffer == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int PtrSize = Instance.WinHelper.PointerSize;
            int HeaderSize = PtrSize + 4 + 4 + 4;
            if (GuestInputLength(in Data) < HeaderSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            ulong WsaBufArrayPtr = ReadPtr(Instance, Data.InputBuffer, 0);
            uint BufferCount = ReadU32(Data.InputBuffer, PtrSize);

            if (WsaBufArrayPtr == 0 || BufferCount == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (BufferCount > MaxTransferBuffers)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            int EntrySize = 2 * PtrSize;
            Span<byte> Entries = Instance.WinHelper.Shared.GetSpan(BufferCount * (uint)EntrySize).Slice(0, (int)BufferCount * EntrySize);
            if (!Instance.ReadMemory(WsaBufArrayPtr, Entries))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong Total = 0;
            for (int i = 0; i < (int)BufferCount; i++)
            {
                (ulong Address, uint Length) = ReadWsabuf(Entries, i, PtrSize);

                if (Length != 0 && Address == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (Length != 0 && !Instance.IsRegionMapped(Address, Length))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Total += Length;
                if (Total > int.MaxValue)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (BufferCount == 1)
            {
                Buffers = new TransferBuffers(ReadWsabuf(Entries, 0, PtrSize).Address, (uint)Total);
            }
            else
            {
                (ulong Address, uint Length)[] Segments = ArrayPool<(ulong Address, uint Length)>.Shared.Rent((int)BufferCount);
                for (int i = 0; i < (int)BufferCount; i++)
                    Segments[i] = ReadWsabuf(Entries, i, PtrSize);

                Buffers = new TransferBuffers(Segments, (int)BufferCount, (uint)Total);
            }

            AfdFlags = ReadU32(Data.InputBuffer, PtrSize + 4);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static (ulong Address, uint Length) ReadWsabuf(ReadOnlySpan<byte> Entries, int Index, int PtrSize)
        {
            ReadOnlySpan<byte> Entry = Entries.Slice(Index * 2 * PtrSize, 2 * PtrSize);
            ulong Address = PtrSize == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(Entry.Slice(8)) : BinaryPrimitives.ReadUInt32LittleEndian(Entry.Slice(4));
            return (Address, BinaryPrimitives.ReadUInt32LittleEndian(Entry));
        }

        private NTSTATUS IoctlSend(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            NTSTATUS Status = ReadTransferInfo(in Data, Instance, out TransferBuffers Buffers, out uint AfdFlags);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            bool Pended = false;
            try
            {
                if (!IsSocketRemoteAllowed(Instance, _socket, true))
                    return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

                if (Buffers.Total == 0)
                {
                    _socket.Send(ReadOnlySpan<byte>.Empty, SocketFlags.None, out SocketError EmptyError);
                    return EmptyError == SocketError.Success ? NTSTATUS.STATUS_SUCCESS : MapSocketError(EmptyError);
                }

                PendingRequests Requests = Instance.WinHelper.AfdRequests;
                int Sent = 0;
                if (!Requests.HasTransfer(this, Send: true) && TrySend(Instance, in Buffers, ref Sent, out Status))
                {
                    Data.Information = (ulong)Sent;
                    return Status;
                }

                // AFD takes all of a blocking or overlapped send.
                if (_nonBlocking && (AfdFlags & AFD_OVERLAPPED) == 0)
                {
                    if (Sent == 0)
                        return NTSTATUS.STATUS_DEVICE_NOT_READY;

                    Data.Information = (ulong)Sent;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Status = Requests.Pend(Instance, new PendingTransfer(Instance, in Data, this, Send: true, Buffers, Sent));
                Pended = Status == NTSTATUS.STATUS_PENDING;
                return Status;
            }
            finally
            {
                if (!Pended)
                    Buffers.Release();
            }
        }

        private bool TrySend(BinaryEmulator Instance, in TransferBuffers Buffers, ref int Sent, out NTSTATUS Status)
        {
            BrovanSocket? Socket = _socket;
            if (Socket == null)
            {
                Status = NTSTATUS.STATUS_INVALID_CONNECTION;
                return true;
            }

            uint Length = Buffers.Total;
            SocketError Error = SocketError.Success;
            while ((uint)Sent < Length)
            {
                int Chunk = (int)Math.Min(Length - (uint)Sent, (uint)NtReadFile.IoChunkBytes);
                byte[] Payload = Instance.WinHelper.Shared.GetBuffer((uint)Chunk);
                if (!Buffers.Read(Instance, (uint)Sent, Payload.AsSpan(0, Chunk)))
                {
                    Status = Sent == 0 ? NTSTATUS.STATUS_ACCESS_VIOLATION : NTSTATUS.STATUS_SUCCESS;
                    return true;
                }

                int Moved = Socket.Send(Payload.AsSpan(0, Chunk), SocketFlags.None, out Error);
                if (Moved > 0)
                {
                    NetworkTrafficPcapCapture.RecordOutbound(Socket, Payload.AsSpan(0, Moved));
                    Sent += Moved;
                }

                if (Error != SocketError.Success || Moved < Chunk)
                    break;
            }

            Status = NTSTATUS.STATUS_SUCCESS;
            if ((uint)Sent < Length && (Error == SocketError.Success || Error == SocketError.WouldBlock))
                return false;

            if (Sent == 0 && Error != SocketError.Success)
                Status = MapSocketError(Error);

            return true;
        }

        private NTSTATUS IoctlReceive(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            NTSTATUS Status = ReadTransferInfo(in Data, Instance, out TransferBuffers Buffers, out uint AfdFlags);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            bool Pended = false;
            try
            {
                if (!IsSocketRemoteAllowed(Instance, _socket, true))
                    return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

                PendingRequests Requests = Instance.WinHelper.AfdRequests;
                if (!Requests.HasTransfer(this, Send: false) && TryReceive(Instance, in Buffers, out Status, out ulong Received))
                {
                    Data.Information = Received;
                    return Status;
                }

                // AFD fails a receive that finds no data on a non-blocking endpoint unless it is overlapped.
                if (_nonBlocking && (AfdFlags & AFD_OVERLAPPED) == 0)
                    return NTSTATUS.STATUS_DEVICE_NOT_READY;

                Status = Requests.Pend(Instance, new PendingTransfer(Instance, in Data, this, Send: false, Buffers, 0));
                Pended = Status == NTSTATUS.STATUS_PENDING;
                return Status;
            }
            finally
            {
                if (!Pended)
                    Buffers.Release();
            }
        }

        private bool TryReceive(BinaryEmulator Instance, in TransferBuffers Buffers, out NTSTATUS Status, out ulong Received)
        {
            Received = 0;
            BrovanSocket? Socket = _socket;
            if (Socket == null)
            {
                Status = NTSTATUS.STATUS_INVALID_CONNECTION;
                return true;
            }

            int Want = (int)Math.Min(Buffers.Total, (uint)NtReadFile.IoChunkBytes);
            byte[] RecvBuffer = Instance.WinHelper.Shared.GetBuffer((uint)Math.Max(Want, 1));
            SocketError Error;
            int Count = 0;
            // A zero-length receive waits for data and leaves it queued. Linux answers a zero-byte receive at once.
            if (Want == 0)
                Socket.Receive(RecvBuffer.AsSpan(0, 1), SocketFlags.Peek, out Error);
            else
                Count = Socket.Receive(RecvBuffer.AsSpan(0, Want), SocketFlags.None, out Error);

            Status = NTSTATUS.STATUS_SUCCESS;
            if (Error == SocketError.WouldBlock)
                return false;

            if (Error != SocketError.Success)
            {
                Status = MapSocketError(Error);
                return true;
            }

            if (Count > 0)
            {
                if (!Buffers.Write(Instance, RecvBuffer.AsSpan(0, Count)))
                {
                    Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                    return true;
                }

                NetworkTrafficPcapCapture.RecordInbound(Socket, RecvBuffer.AsSpan(0, Count));
            }

            Received = (ulong)Count;
            return true;
        }

        private NTSTATUS IoctlPartialDisconnect(in DeviceData Data)
        {
            if (Data.InputBuffer == null || GuestInputLength(in Data) < AfdDisconnectInfoSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (_socket?.SocketType == SocketType.Dgram)
                return NTSTATUS.STATUS_SUCCESS;

            if (_socket == null || !_socket.Connected)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint DisconnectType = ReadU32(Data.InputBuffer, 0);
            try
            {
                if ((DisconnectType & AFD_DISCONNECT_RECV) != 0)
                    _socket.Shutdown(SocketShutdown.Receive);

                if ((DisconnectType & AFD_DISCONNECT_SEND) != 0)
                    _socket.Shutdown(SocketShutdown.Send);

                return NTSTATUS.STATUS_SUCCESS;
            }
            catch (SocketException Ex)
            {
                return MapSocketError(Ex.SocketErrorCode);
            }
        }

        private NTSTATUS IoctlSetInfo(in DeviceData Data)
        {
            if (Data.InputBuffer == null || GuestInputLength(in Data) < AfdInfoSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (ReadU32(Data.InputBuffer, 0) == AFD_INFO_BLOCKING_MODE)
                _nonBlocking = Data.InputBuffer[8] != 0;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: AfdInitializeData doubles the default windows on a server.
        private static uint DefaultWindowBytes => WindowsVersionInfo.ProductTypeWinNt == 1 ? 0x10000u : 0x20000u;

        // AFD_INFORMATION: the type, then the value at +8.
        private NTSTATUS IoctlGetInformation(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer == null || GuestInputLength(in Data) < AfdInfoSize || Data.OutputBuffer == null || GuestOutputLength(in Data) < AfdInfoSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            uint Type = ReadU32(Data.InputBuffer, 0);
            uint Value;
            switch (Type)
            {
                case AFD_INFO_SENDS_PENDING:
                    Value = 0;
                    break;

                case AFD_INFO_RECEIVE_WINDOW_SIZE:
                case AFD_INFO_SEND_WINDOW_SIZE:
                    Value = DefaultWindowBytes;
                    break;

                case AFD_INFO_CONNECT_TIME:
                    Value = _connectedAt == 0 ? uint.MaxValue : (uint)((Instance.GetEmulatedSystemTimeFileTimeUtc() - _connectedAt) / 10000000);
                    break;

                case AFD_INFO_MAX_SEND_SIZE:
                case AFD_INFO_MAX_PATH_SEND_SIZE:
                    Value = TranslateWinType(WinType) == SocketType.Stream ? uint.MaxValue
                        : TranslateWinAf(WinAf) == AddressFamily.InterNetworkV6 ? MaxDatagramBytesV6 : MaxDatagramBytesV4;
                    break;

                case AFD_INFO_GROUP_ID_AND_TYPE:
                case AFD_INFO_DELIVERY_STATUS:
                    if ((Instance.Settings.Flags & LogFlags.General) != 0)
                        Instance.TriggerEventMessage($"[!] AFD information type not implemented: {Type}.", LogFlags.General);
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            Span<byte> Output = Data.OutputBuffer.AsSpan(0, (int)AfdInfoSize);
            Output.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Output, Type);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(8), Value);
            Data.Information = AfdInfoSize;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: no TDI address or connection object here, so both handles are -1.
        private static NTSTATUS IoctlQueryHandles(ref DeviceData Data, BinaryEmulator Instance)
        {
            const uint QueryAddressHandle = 1;
            const uint QueryConnectionHandle = 2;

            int Bytes = 2 * Instance.WinHelper.PointerSize;
            if (Data.InputBuffer == null || GuestInputLength(in Data) < 4 || Data.OutputBuffer == null || GuestOutputLength(in Data) < Bytes)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            uint Flags = ReadU32(Data.InputBuffer, 0);
            if (Flags == 0 || (Flags & ~(QueryAddressHandle | QueryConnectionHandle)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Data.OutputBuffer.AsSpan(0, Bytes).Fill(0xFF);
            Data.Information = (ulong)Bytes;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: the output buffer marks the remote address inside the context.
        private NTSTATUS IoctlSetContext(in DeviceData Data)
        {
            uint Size = GuestInputLength(in Data);
            if (Data.UserBuffer != 0)
            {
                ulong Offset = Data.UserBuffer - Data.InputPointer;
                if (Data.UserBuffer < Data.InputPointer || Offset > 0xFFFF || Data.OutputLength > 0xFFFF ||
                    Data.OutputLength > Size || Offset > Size - Data.OutputLength)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (Size > MaxContextBytes)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            if (Size != 0)
                _context = Data.InputBuffer.AsSpan(0, (int)Size).ToArray();
            else if (_context != null)
                _context = Array.Empty<byte>();

            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlGetContext(ref DeviceData Data)
        {
            if (_context == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Room = GuestOutputLength(in Data);
            int Copied = (int)Math.Min(Room, (uint)_context.Length);
            if (Copied != 0)
                _context.AsSpan(0, Copied).CopyTo(Data.OutputBuffer);

            Data.Information = (ulong)_context.Length;
            return Room < _context.Length ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlGetAddress(ref DeviceData Data)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            uint OutputLength = GuestOutputLength(in Data);
            if (Data.OutputBuffer == null || OutputLength < 2)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            try
            {
                if (_socket.LocalEndPoint is not IPEndPoint LocalEndPoint)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                byte[] SockAddr = BuildSockaddr(LocalEndPoint);

                if (SockAddr.Length == 0)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                if (OutputLength < SockAddr.Length)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Array.Clear(Data.OutputBuffer, 0, (int)OutputLength);
                Buffer.BlockCopy(SockAddr, 0, Data.OutputBuffer, 0, SockAddr.Length);
                Data.Information = (ulong)SockAddr.Length;
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        private NTSTATUS IoctlTransport(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer == null || GuestInputLength(in Data) < TransportBufferOffset + 2 * Instance.WinHelper.PointerSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Code = ReadU32(Data.InputBuffer, TransportIoctlCodeOffset);
            // No route table to sort with. A failure keeps the list for ws2_32, a zeroed reply empties it.
            if (Code == SioAddressListSort)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            if (ReadU32(Data.InputBuffer, TransportLevelOffset) == IpProtoIpv6 && Code == Ipv6V6Only)
            {
                uint Type = ReadU32(Data.InputBuffer, 0);
                if (Type == TransportSetOption)
                    return SetV6Only(in Data, Instance);

                if (Type == TransportGetOption)
                    return GetV6Only(ref Data);
            }

            return ReplyZeroed(ref Data);
        }

        // tcpip keeps IPV6_V6ONLY for any family and fixes it at bind.
        private NTSTATUS SetV6Only(in DeviceData Data, BinaryEmulator Instance)
        {
            ulong ValuePtr = ReadPtr(Instance, Data.InputBuffer, TransportBufferOffset);
            ulong ValueLength = ReadPtr(Instance, Data.InputBuffer, TransportBufferOffset + Instance.WinHelper.PointerSize);

            Span<byte> Value = stackalloc byte[sizeof(uint)];
            Value.Clear();
            int Copied = (int)Math.Min(ValueLength, sizeof(uint));
            if (Copied != 0 && !Instance.ReadMemory(ValuePtr, Value.Slice(0, Copied)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ValueLength < sizeof(uint))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (_socket != null && _socket.IsBound)
                return NTSTATUS.STATUS_ADDRESS_ALREADY_ASSOCIATED;

            _v6Only = BinaryPrimitives.ReadUInt32LittleEndian(Value) != 0;
            if (_socket?.AddressFamily == AddressFamily.InterNetworkV6)
                _socket.DualMode = !_v6Only;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS GetV6Only(ref DeviceData Data)
        {
            if (GuestOutputLength(in Data) < sizeof(uint))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(0, sizeof(uint)), _v6Only ? 1u : 0u);
            Data.Information = sizeof(uint);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlGetRemoteAddress(ref DeviceData Data)
        {
            if (_socket == null || !_socket.Connected)
                return NTSTATUS.STATUS_INVALID_CONNECTION;

            IPEndPoint? Remote;
            try
            {
                Remote = _socket.RemoteEndPoint as IPEndPoint;
            }
            catch (SocketException)
            {
                return NTSTATUS.STATUS_INVALID_CONNECTION;
            }

            byte[] SockAddr = Remote == null ? Array.Empty<byte>() : BuildSockaddr(Remote);
            if (SockAddr.Length == 0)
                return NTSTATUS.STATUS_INVALID_CONNECTION;

            if (GuestOutputLength(in Data) < SockAddr.Length)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Buffer.BlockCopy(SockAddr, 0, Data.OutputBuffer, 0, SockAddr.Length);
            Data.Information = (ulong)SockAddr.Length;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReplyZeroed(ref DeviceData Data)
        {
            uint OutputLength = GuestOutputLength(in Data);
            if (OutputLength != 0)
                Array.Clear(Data.OutputBuffer, 0, (int)OutputLength);

            Data.Information = OutputLength;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlPoll(ref DeviceData Data, BinaryEmulator Instance)
        {
            uint InputLength = GuestInputLength(in Data);
            if (Data.InputBuffer == null || InputLength < PollHeaderSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int PointerSize = Instance.WinHelper.PointerSize;
            uint Count = ReadU32(Data.InputBuffer, PollCountOffset);
            if (Count == 0 || (InputLength - PollHeaderSize) / (uint)PollEntrySize(PointerSize) < Count ||
                Data.OutputBuffer == null || Data.OutputLength < InputLength)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            long Timeout = BinaryPrimitives.ReadInt64LittleEndian(Data.InputBuffer.AsSpan(0, sizeof(long)));
            uint ExclusiveField = ReadU32(Data.InputBuffer, PollExclusiveOffset);
            bool Exclusive = (byte)ExclusiveField != 0;
            if (Exclusive && !IsInfinitePollTimeout(Timeout))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Count > MaxPollHandles)
                return NTSTATUS.STATUS_TOO_MANY_OPENED_FILES;

            Span<byte> Output = Data.OutputBuffer.AsSpan(0, PollOutputBytes((int)Count, PointerSize));
            int Ready = 0;
            for (int i = 0; i < (int)Count; i++)
            {
                NTSTATUS Status = ResolvePollEntry(Instance, Data.InputBuffer, i, out ulong Handle, out uint Events, out AfdDevice? Endpoint);
                if (Endpoint == null)
                    return Status;

                uint Triggered = Endpoint.CheckPollEvents(Events, out NTSTATUS EntryStatus);
                if (Triggered != 0)
                    WritePollEntry(Output, Ready++, Handle, Triggered, EntryStatus, PointerSize);
            }

            PendingRequests Requests = Instance.WinHelper.AfdRequests;
            if (Exclusive)
            {
                for (int i = 0; i < (int)Count; i++)
                {
                    ResolvePollEntry(Instance, Data.InputBuffer, i, out _, out _, out AfdDevice? Endpoint);
                    Requests.ReplaceExclusive(Instance, Endpoint!);
                }
            }

            if (Ready != 0 || Timeout == 0)
            {
                WritePollHeader(Output, Timeout, (uint)Ready, ExclusiveField);
                Data.Information = (ulong)PollOutputBytes(Ready, PointerSize);
                return NTSTATUS.STATUS_SUCCESS;
            }

            PollEntry[] Entries = new PollEntry[Count];
            for (int i = 0; i < Entries.Length; i++)
            {
                ResolvePollEntry(Instance, Data.InputBuffer, i, out ulong Handle, out uint Events, out AfdDevice? Endpoint);
                Entries[i] = new PollEntry(Handle, Events, Endpoint!);
            }

            long Deadline = IsInfinitePollTimeout(Timeout) ? -1 : Instance.CreateEmulatedDeadlineMilliseconds(PollTimeoutMs(Instance, Timeout));
            return Requests.Pend(Instance, new PendingPoll(Instance, in Data, Entries, Timeout, ExclusiveField, Exclusive, Deadline));
        }

        private static NTSTATUS ResolvePollEntry(BinaryEmulator Instance, byte[] Input, int Index, out ulong Handle, out uint Events, out AfdDevice? Endpoint)
        {
            int PointerSize = Instance.WinHelper.PointerSize;
            int Offset = PollHeaderSize + Index * PollEntrySize(PointerSize);
            Handle = ReadPtr(Instance, Input, Offset);
            Events = ReadU32(Input, Offset + PointerSize);
            return ResolveConnectEndpoint(Instance, Handle, out Endpoint);
        }

        private static bool IsInfinitePollTimeout(long Timeout) => (uint)((ulong)Timeout >> 32) == 0x7FFFFFFF;

        private static int PollEntrySize(int PointerSize) => PointerSize + 2 * sizeof(uint);

        private static int PollOutputBytes(int Entries, int PointerSize) => PollHeaderSize + Entries * PollEntrySize(PointerSize);

        private static void WritePollHeader(Span<byte> Output, long Timeout, uint Count, uint ExclusiveField)
        {
            BinaryPrimitives.WriteInt64LittleEndian(Output, Timeout);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(PollCountOffset), Count);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(PollExclusiveOffset), ExclusiveField);
        }

        private static void WritePollEntry(Span<byte> Output, int Index, ulong Handle, uint Triggered, NTSTATUS EntryStatus, int PointerSize)
        {
            Span<byte> Entry = Output.Slice(PollOutputBytes(Index, PointerSize), PollEntrySize(PointerSize));
            if (PointerSize == sizeof(ulong))
                BinaryPrimitives.WriteUInt64LittleEndian(Entry, Handle);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Entry, (uint)Handle);

            BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(PointerSize), Triggered);
            BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(PointerSize + sizeof(uint)), (uint)EntryStatus);
        }

        private static int FillPollOutput(Span<byte> Output, PollEntry[] Entries, AfdDevice? Closing, int PointerSize)
        {
            int Ready = 0;
            for (int i = 0; i < Entries.Length; i++)
            {
                NTSTATUS EntryStatus = NTSTATUS.STATUS_SUCCESS;
                uint Triggered = Closing == null
                    ? Entries[i].Endpoint.CheckPollEvents(Entries[i].Events, out EntryStatus)
                    : ReferenceEquals(Entries[i].Endpoint, Closing) ? AFD_POLL_LOCAL_CLOSE : 0;

                if (Triggered != 0)
                    WritePollEntry(Output, Ready++, Entries[i].Handle, Triggered, EntryStatus, PointerSize);
            }

            return Ready;
        }

        private uint CheckPollEvents(uint Requested, out NTSTATUS EntryStatus)
        {
            EntryStatus = NTSTATUS.STATUS_SUCCESS;
            BrovanSocket? HostSocket = _socket;
            if (HostSocket == null || _connectPending)
                return 0;

            if ((int)_connectFailure < 0 && !HostSocket.Connected)
            {
                EntryStatus = _connectFailure;
                return Requested & AFD_POLL_CONNECT_FAIL;
            }

            bool ReadReady = false;
            bool WriteReady = false;
            bool ErrorReady = false;

            try
            {
                ReadReady = (Requested & PollReadEvents) != 0 && HostSocket.Poll(0, SelectMode.SelectRead);
                WriteReady = (Requested & PollWriteEvents) != 0 && HostSocket.Poll(0, SelectMode.SelectWrite);
                ErrorReady = (Requested & PollErrorEvents) != 0 && HostSocket.Poll(0, SelectMode.SelectError);
            }
            catch
            {
                ErrorReady = true;
            }

            return MapPollEventsToTriggered(Requested, ReadReady, WriteReady, ErrorReady, IsListening);
        }

        // Wider modes would wake the watcher again and again on a socket that stays ready.
        private byte WatchModes(uint Requested)
        {
            BrovanSocket? HostSocket = _socket;
            if (HostSocket == null || _connectPending || ((int)_connectFailure < 0 && !HostSocket.Connected))
                return 0;

            byte Modes = 0;
            if (MapPollEventsToTriggered(Requested, true, false, false, IsListening) != 0)
                Modes |= HostSocketWatcher.WatchRead;

            if (MapPollEventsToTriggered(Requested, false, true, false, IsListening) != 0)
                Modes |= HostSocketWatcher.WatchWrite;

            if (MapPollEventsToTriggered(Requested, false, false, true, IsListening) != 0)
                Modes |= HostSocketWatcher.WatchError;

            return Modes;
        }

        private static int PollTimeoutMs(BinaryEmulator Instance, long Timeout)
        {
            long Delta = Timeout < 0
                ? (Timeout == long.MinValue ? long.MaxValue : -Timeout)
                : Timeout - Instance.GetEmulatedSystemTimeFileTimeUtc();

            if (Delta <= 0)
                return 0;

            long Milliseconds = Delta / 10000 + (Delta % 10000 != 0 ? 1 : 0);
            return Milliseconds > int.MaxValue ? int.MaxValue : (int)Milliseconds;
        }

        public NTSTATUS Handle(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            NetworkAccessPolicy Policy = Instance.Settings.GetNetworkPolicy();
            if (!Policy.HasAnyAccess())
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            if (!IsAfdRequest(Ioctl))
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            _policy = Policy;

            int Request = DecodeRequest(Ioctl);

            try
            {
                return Request switch
                {
                    AFD_BIND => IoctlBind(ref Data, Instance),
                    AFD_CONNECT => IoctlConnect(ref Data, Instance),
                    AFD_START_LISTEN => IoctlListen(ref Data, Instance),
                    AFD_WAIT_FOR_LISTEN => IoctlWaitForListen(ref Data, Instance),
                    AFD_ACCEPT => IoctlAccept(ref Data, Instance),
                    AFD_SUPER_ACCEPT => IoctlSuperAccept(ref Data, Instance),
                    AFD_SEND => IoctlSend(ref Data, Instance),
                    AFD_RECEIVE => IoctlReceive(ref Data, Instance),
                    AFD_GET_ADDRESS => IoctlGetAddress(ref Data),
                    AFD_QUERY_HANDLES => IoctlQueryHandles(ref Data, Instance),
                    AFD_GET_REMOTE_ADDRESS => IoctlGetRemoteAddress(ref Data),
                    AFD_GET_CONTEXT => IoctlGetContext(ref Data),
                    AFD_SET_CONTEXT => IoctlSetContext(in Data),
                    AFD_GET_INFORMATION => IoctlGetInformation(ref Data, Instance),
                    AFD_SUPER_CONNECT => IoctlSuperConnect(ref Data, Instance),
                    AFD_POLL => IoctlPoll(ref Data, Instance),
                    AFD_SET_INFO => IoctlSetInfo(in Data),
                    AFD_PARTIAL_DISCONNECT => IoctlPartialDisconnect(in Data),
                    AFD_EVENT_SELECT => NTSTATUS.STATUS_SUCCESS,
                    AFD_ENUM_NETWORK_EVENTS => NTSTATUS.STATUS_SUCCESS,
                    AFD_RECEIVE_DATAGRAM => Policy.Mode == NetworkAccessMode.Full ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NETWORK_UNREACHABLE,
                    AFD_SEND_DATAGRAM => Policy.Mode == NetworkAccessMode.Full ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NETWORK_UNREACHABLE,
                    AFD_TRANSPORT_IOCTL => IoctlTransport(ref Data, Instance),
                    AFD_ROUTING_INTERFACE_QUERY or AFD_ADDRESS_LIST_QUERY => ReplyZeroed(ref Data),
                    _ => ReportUnmodeled(Instance, Request)
                };
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        private static NTSTATUS ReportUnmodeled(BinaryEmulator Instance, int Request)
        {
            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[!] AFD request not implemented: {Request}.", LogFlags.General);

            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        internal static NTSTATUS HandleConnectHelper(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (!Instance.Settings.GetNetworkPolicy().HasAnyAccess())
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            if (Ioctl != IoctlAfdConnect)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            NTSTATUS Status = CheckConnectLengths(in Data, Instance);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = ResolveConnectEndpoint(Instance, ReadPtr(Instance, Data.InputBuffer, 2 * Instance.WinHelper.PointerSize), out AfdDevice? Endpoint);
            return Endpoint == null ? Status : StartConnect(Endpoint, ref Data, Instance);
        }

        private static NTSTATUS CheckConnectLengths(in DeviceData Data, BinaryEmulator Instance)
        {
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;

            if (Data.OutputLength != 0 && Data.OutputLength < 2 * PointerSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Data.InputBuffer == null || GuestInputLength(in Data) < 3 * PointerSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS StartConnect(AfdDevice Endpoint, ref DeviceData Data, BinaryEmulator Instance)
        {
            int PointerSize = Instance.WinHelper.PointerSize;
            uint HeaderSize = 3 * (uint)PointerSize;
            uint InputLength = GuestInputLength(in Data);

            if (InputLength - HeaderSize < 2)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            IPEndPoint? Remote = ParseSockaddr(Data.InputBuffer, InputLength, (int)HeaderSize);
            if (Remote == null)
                return NTSTATUS.STATUS_INVALID_ADDRESS;

            if (Data.UserBuffer != 0 && !Instance.IsRegionMapped(Data.UserBuffer, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // A root endpoint means a multipoint join, which uses another IOCTL.
            if (ReadPtr(Instance, Data.InputBuffer, PointerSize) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            BrovanSocket? Socket = Endpoint._socket;
            if (Endpoint._connectPending || Endpoint.IsListening || Socket == null || !Socket.IsBound ||
                (Socket.SocketType == SocketType.Stream && Socket.Connected))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!IsEndpointAllowed(Instance, Remote))
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            if ((int)Endpoint._connectFailure < 0)
            {
                NTSTATUS Rebound = Endpoint.RebindAfterFailedConnect(Instance);
                if (Rebound != NTSTATUS.STATUS_SUCCESS)
                    return Rebound;

                Socket = Endpoint._socket!;
            }

            return new HostConnect(Instance, Endpoint, in Data, WritesStatus: true).Start(Socket, Remote);
        }

        private NTSTATUS IoctlSuperConnect(ref DeviceData Data, BinaryEmulator Instance)
        {
            uint InputLength = GuestInputLength(in Data);
            if (Data.InputBuffer == null || InputLength < SuperConnectMinInput)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            IPEndPoint? Remote = ParseSockaddr(Data.InputBuffer, InputLength, SuperConnectAddressOffset);
            if (Remote == null)
                return NTSTATUS.STATUS_INVALID_ADDRESS;

            HostConnect Connect = new HostConnect(Instance, this, in Data, WritesStatus: false);
            NTSTATUS Status = Connect.CopySendData(in Data, Instance);

            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = CheckSuperConnectEndpoint();

            if (Status == NTSTATUS.STATUS_SUCCESS && !IsEndpointAllowed(Instance, Remote))
                Status = NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            if (Status == NTSTATUS.STATUS_SUCCESS && (int)_connectFailure < 0)
                Status = RebindAfterFailedConnect(Instance);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Connect.ReleaseSendData();
                return Status;
            }

            return Connect.Start(_socket!, Remote);
        }

        private NTSTATUS CheckSuperConnectEndpoint()
        {
            if (_connectPending || IsListening || _socket == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (_socket.Connected)
                return NTSTATUS.STATUS_CONNECTION_ACTIVE;

            return _socket.SocketType == SocketType.Stream && _socket.IsBound ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // tcpip fails this connect after it pends.
        private bool HasNoPathTo(BrovanSocket Socket, IPEndPoint Remote) =>
            _v6Only && Socket.AddressFamily == AddressFamily.InterNetworkV6 && Remote.Address.IsIPv4MappedToIPv6;

        // A host can replace a socket that failed to connect with an unbound one. AFD keeps the endpoint bound.
        private NTSTATUS RebindAfterFailedConnect(BinaryEmulator Instance)
        {
            try
            {
                EndPoint? Local = _socket?.LocalEndPoint;
                if (Local == null)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ReleaseSocket(Instance);
                EnsureSocket();
                _socket!.Bind(Local);
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch (Exception Ex)
            {
                return Ex is SocketException SocketEx ? MapSocketError(SocketEx.SocketErrorCode) : NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        private static NTSTATUS ResolveConnectEndpoint(BinaryEmulator Instance, ulong Handle, out AfdDevice? Endpoint)
        {
            Endpoint = null;

            if (HandleManager.IsCurrentProcessPseudoHandle(Handle) || HandleManager.IsCurrentThreadPseudoHandle(Handle))
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (!Instance.WinHelper.HandleManager.TryGetHandle(Handle, out HandleEntry Entry) || Entry.Object == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Entry.Object is not WinFile File)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (File.Handler?.Target is not AfdDevice Device)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Endpoint = Device;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS MapSocketError(SocketError Error) => Error switch
        {
            SocketError.Success => NTSTATUS.STATUS_SUCCESS,
            SocketError.ConnectionRefused => NTSTATUS.STATUS_CONNECTION_REFUSED,
            SocketError.TimedOut => NTSTATUS.STATUS_IO_TIMEOUT,
            SocketError.NetworkUnreachable => NTSTATUS.STATUS_NETWORK_UNREACHABLE,
            SocketError.HostUnreachable => NTSTATUS.STATUS_HOST_UNREACHABLE,
            SocketError.HostDown => NTSTATUS.STATUS_HOST_DOWN,
            SocketError.ConnectionReset => NTSTATUS.STATUS_CONNECTION_RESET,
            SocketError.ConnectionAborted => NTSTATUS.STATUS_CONNECTION_ABORTED,
            SocketError.AddressAlreadyInUse => NTSTATUS.STATUS_ADDRESS_ALREADY_EXISTS,
            SocketError.AddressNotAvailable => NTSTATUS.STATUS_INVALID_ADDRESS_COMPONENT,
            SocketError.AccessDenied => NTSTATUS.STATUS_ACCESS_DENIED,
            SocketError.OperationAborted => NTSTATUS.STATUS_CANCELLED,
            SocketError.Shutdown => NTSTATUS.STATUS_PIPE_DISCONNECTED,
            _ => NTSTATUS.STATUS_UNSUCCESSFUL
        };

        internal readonly struct PollEntry
        {
            internal readonly ulong Handle;
            internal readonly uint Events;
            internal readonly AfdDevice Endpoint;

            internal PollEntry(ulong Handle, uint Events, AfdDevice Endpoint)
            {
                this.Handle = Handle;
                this.Events = Events;
                this.Endpoint = Endpoint;
            }
        }

        internal sealed class PendingPoll : ParkedIoRequest
        {
            internal readonly WinPendingIo Io;
            internal readonly ulong Output;
            internal readonly PollEntry[] Entries;
            internal readonly long Timeout;
            internal readonly uint ExclusiveField;
            internal readonly bool Exclusive;
            internal readonly long Deadline;

            internal PendingPoll(BinaryEmulator Instance, in DeviceData Data, PollEntry[] Entries, long Timeout, uint ExclusiveField, bool Exclusive, long Deadline)
            {
                Io = new WinPendingIo(in Data, Instance.CurrentThreadId, Instance.WinHelper.GetEventByHandle(Data.EventHandle, AccessMask.GiveTemp));
                Output = Data.UserBuffer;
                this.Entries = Entries;
                this.Timeout = Timeout;
                this.ExclusiveField = ExclusiveField;
                this.Exclusive = Exclusive;
                this.Deadline = Deadline;
            }

            internal override string WaitLabel => "afd-poll";

            internal bool Names(AfdDevice Endpoint)
            {
                for (int i = 0; i < Entries.Length; i++)
                {
                    if (ReferenceEquals(Entries[i].Endpoint, Endpoint))
                        return true;
                }

                return false;
            }
        }

        internal sealed class PendingTransfer : ParkedIoRequest
        {
            internal readonly WinPendingIo Io;
            internal readonly AfdDevice Endpoint;
            internal readonly bool Send;
            internal readonly TransferBuffers Buffers;
            internal int Sent;

            // AfdBReceive gave it to the transport, not to the AFD queue.
            internal bool Posted;

            internal PendingTransfer(BinaryEmulator Instance, in DeviceData Data, AfdDevice Endpoint, bool Send, in TransferBuffers Buffers, int Sent)
            {
                Io = new WinPendingIo(in Data, Instance.CurrentThreadId, Instance.WinHelper.GetEventByHandle(Data.EventHandle, AccessMask.GiveTemp));
                this.Endpoint = Endpoint;
                this.Send = Send;
                this.Buffers = Buffers;
                this.Sent = Sent;
            }

            internal override string WaitLabel => Send ? "afd-send" : "afd-receive";
        }

        internal sealed class PendingAccept : ParkedIoRequest
        {
            internal readonly WinPendingIo Io;
            internal readonly AfdDevice Listener;
            internal readonly AfdDevice Target;
            internal readonly ulong Output;
            internal readonly bool FixAddressAlignment;
            internal readonly uint ReceiveLength;
            internal readonly uint LocalLength;
            internal readonly uint RemoteLength;

            // The connection is in Target, and the request waits for its first data.
            internal bool Accepted;

            internal PendingAccept(BinaryEmulator Instance, in DeviceData Data, AfdDevice Listener, AfdDevice Target, bool FixAddressAlignment,
                uint ReceiveLength, uint LocalLength, uint RemoteLength)
            {
                Io = new WinPendingIo(in Data, Instance.CurrentThreadId, Instance.WinHelper.GetEventByHandle(Data.EventHandle, AccessMask.GiveTemp));
                Output = Data.UserBuffer;
                this.Listener = Listener;
                this.Target = Target;
                this.FixAddressAlignment = FixAddressAlignment;
                this.ReceiveLength = ReceiveLength;
                this.LocalLength = LocalLength;
                this.RemoteLength = RemoteLength;
            }

            internal AfdDevice WaitsOn => Accepted ? Target : Listener;

            internal override string WaitLabel => Accepted ? "afd-accept-receive" : "afd-accept";
        }

        internal sealed class PendingRequests : IDisposable
        {
            private readonly List<PendingPoll> Polls = new();
            private readonly List<PendingTransfer> Transfers = new();
            private readonly List<PendingAccept> Accepts = new();
            private readonly List<AfdDevice> ReadyEndpoints = new();
            private HostSocketWatcher? Watcher;
            private long EarliestDeadline = -1;

            internal int Count => Polls.Count + Transfers.Count + Accepts.Count;

            internal bool HasWork => Count != 0 || (Watcher != null && Watcher.HasReady);

            internal NTSTATUS Pend(BinaryEmulator Instance, PendingPoll Poll)
            {
                if (!TryStartWatcher(Instance))
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                Polls.Add(Poll);
                if (Poll.Deadline >= 0 && (EarliestDeadline < 0 || Poll.Deadline < EarliestDeadline))
                    EarliestDeadline = Poll.Deadline;

                for (int i = 0; i < Poll.Entries.Length; i++)
                {
                    AfdDevice Endpoint = Poll.Entries[i].Endpoint;
                    Watcher!.WatchAlso(Endpoint, Endpoint._socket, Endpoint.WatchModes(Poll.Entries[i].Events));
                }

                return Park(Instance, Poll, in Poll.Io);
            }

            internal NTSTATUS Pend(BinaryEmulator Instance, PendingTransfer Transfer)
            {
                if (!TryStartWatcher(Instance))
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                Transfer.Posted = !Transfer.Send && Transfer.Buffers.Total != 0 && !HasQueuedReceive(Transfer.Endpoint);
                Transfers.Add(Transfer);
                Watcher!.WatchAlso(Transfer.Endpoint, Transfer.Endpoint._socket, TransferModes(Transfer));
                return Park(Instance, Transfer, in Transfer.Io);
            }

            // NT: a waiting connection is taken on the next pass, so the call still pends.
            internal NTSTATUS Pend(BinaryEmulator Instance, PendingAccept Accept)
            {
                if (!TryStartWatcher(Instance))
                {
                    Accept.Target._superAcceptTarget = false;
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                }

                Accepts.Add(Accept);
                Watcher!.WatchAlso(Accept.Listener, Accept.Listener._socket, HostSocketWatcher.WatchRead);
                return Park(Instance, Accept, in Accept.Io);
            }

            private static NTSTATUS Park(BinaryEmulator Instance, ParkedIoRequest Request, in WinPendingIo Io)
            {
                if (Io.File.Synchronous)
                    Instance.WinHelper.ParkForIoRequest(Request);

                return NTSTATUS.STATUS_PENDING;
            }

            private bool TryStartWatcher(BinaryEmulator Instance)
            {
                Watcher ??= new HostSocketWatcher(Instance.WakeSignal);
                return Watcher.TryStart();
            }

            private static byte TransferModes(PendingTransfer Transfer) =>
                Transfer.Send ? HostSocketWatcher.WatchWrite : HostSocketWatcher.WatchRead;

            // AFD keeps the sends and the receives of one endpoint in order.
            internal bool HasTransfer(AfdDevice Endpoint, bool Send)
            {
                for (int i = 0; i < Transfers.Count; i++)
                {
                    if (ReferenceEquals(Transfers[i].Endpoint, Endpoint) && Transfers[i].Send == Send)
                        return true;
                }

                return false;
            }

            private bool HasQueuedReceive(AfdDevice Endpoint)
            {
                for (int i = 0; i < Transfers.Count; i++)
                {
                    PendingTransfer Transfer = Transfers[i];
                    if (ReferenceEquals(Transfer.Endpoint, Endpoint) && !Transfer.Send && !Transfer.Posted)
                        return true;
                }

                return false;
            }

            internal void Service(BinaryEmulator Instance)
            {
                if (Watcher != null && Watcher.HasReady)
                {
                    Watcher.TakeReady(ReadyEndpoints);
                    for (int i = 0; i < ReadyEndpoints.Count; i++)
                        Recheck(Instance, ReadyEndpoints[i]);

                    ReadyEndpoints.Clear();
                }

                if (EarliestDeadline >= 0 && BinaryEmulator.IsDeadlineExpired(EarliestDeadline, Instance.EmulatedTickCount64))
                    EndExpiredPolls(Instance);
            }

            internal void Recheck(BinaryEmulator Instance, AfdDevice Endpoint)
            {
                for (int i = 0; i < Polls.Count; i++)
                {
                    PendingPoll Poll = Polls[i];
                    if (!Poll.Names(Endpoint))
                        continue;

                    if (!Instance.WinHelper.IsPendingIoLive(in Poll.Io))
                    {
                        Polls.RemoveAt(i--);
                        End(Instance, Poll, NTSTATUS.STATUS_CANCELLED);
                        continue;
                    }

                    if (TryEndReady(Instance, Poll, null))
                        Polls.RemoveAt(i--);
                }

                bool ReceiveWaits = false;
                bool SendWaits = false;
                for (int i = 0; i < Transfers.Count; i++)
                {
                    PendingTransfer Transfer = Transfers[i];
                    if (!ReferenceEquals(Transfer.Endpoint, Endpoint) || (Transfer.Send ? SendWaits : ReceiveWaits))
                        continue;

                    if (TryFinish(Instance, Transfer))
                    {
                        Transfers.RemoveAt(i--);
                        continue;
                    }

                    if (Transfer.Send)
                        SendWaits = true;
                    else
                        ReceiveWaits = true;
                }

                // Accepts on one listener complete in issue order.
                bool AcceptWaits = false;
                for (int i = 0; i < Accepts.Count; i++)
                {
                    PendingAccept Accept = Accepts[i];
                    if (!ReferenceEquals(Accept.WaitsOn, Endpoint) || (AcceptWaits && !Accept.Accepted))
                        continue;

                    if (TryFinish(Instance, Accept))
                    {
                        Accepts.RemoveAt(i--);
                        continue;
                    }

                    if (Accept.Accepted)
                        Rearm(Accept.Target);
                    else
                        AcceptWaits = true;
                }

                Rearm(Endpoint);
            }

            private void Rearm(AfdDevice Endpoint)
            {
                if (Watcher == null)
                    return;

                byte Modes = 0;
                for (int i = 0; i < Polls.Count; i++)
                {
                    PollEntry[] Entries = Polls[i].Entries;
                    for (int e = 0; e < Entries.Length; e++)
                    {
                        if (ReferenceEquals(Entries[e].Endpoint, Endpoint))
                            Modes |= Endpoint.WatchModes(Entries[e].Events);
                    }
                }

                for (int i = 0; i < Transfers.Count; i++)
                {
                    if (ReferenceEquals(Transfers[i].Endpoint, Endpoint))
                        Modes |= TransferModes(Transfers[i]);
                }

                for (int i = 0; i < Accepts.Count; i++)
                {
                    if (ReferenceEquals(Accepts[i].WaitsOn, Endpoint))
                        Modes |= HostSocketWatcher.WatchRead;
                }

                Watcher.Watch(Endpoint, Endpoint._socket, Modes);
            }

            private static bool TryFinish(BinaryEmulator Instance, PendingAccept Accept)
            {
                if (!Instance.WinHelper.IsPendingIoLive(in Accept.Io))
                {
                    End(Instance, Accept, NTSTATUS.STATUS_CANCELLED, 0);
                    return true;
                }

                NTSTATUS Status;
                if (!Accept.Accepted)
                {
                    if (!Accept.Listener.TryTakeConnection(Instance, Accept, out Status))
                        return false;

                    if (Status != NTSTATUS.STATUS_SUCCESS || Accept.ReceiveLength == 0)
                    {
                        End(Instance, Accept, Status, 0);
                        return true;
                    }

                    Accept.Accepted = true;
                }

                ulong Received;
                try
                {
                    if (!Accept.Target.TryReceive(Instance, new TransferBuffers(Accept.Output, Accept.ReceiveLength), out Status, out Received))
                        return false;
                }
                catch (Exception Ex)
                {
                    Utils.LogError($"AFD {Accept.WaitLabel} failed on the host: {Ex.Message}");
                    Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                    Received = 0;
                }

                End(Instance, Accept, Status, Received);
                return true;
            }

            private static bool TryFinish(BinaryEmulator Instance, PendingTransfer Transfer)
            {
                if (!Instance.WinHelper.IsPendingIoLive(in Transfer.Io))
                {
                    End(Instance, Transfer, NTSTATUS.STATUS_CANCELLED, 0);
                    return true;
                }

                NTSTATUS Status;
                ulong Information;
                try
                {
                    if (Transfer.Send)
                    {
                        if (!Transfer.Endpoint.TrySend(Instance, in Transfer.Buffers, ref Transfer.Sent, out Status))
                            return false;

                        Information = (ulong)Transfer.Sent;
                    }
                    else if (!Transfer.Endpoint.TryReceive(Instance, in Transfer.Buffers, out Status, out Information))
                    {
                        return false;
                    }
                }
                catch (Exception Ex)
                {
                    Utils.LogError($"AFD {Transfer.WaitLabel} failed on the host: {Ex.Message}");
                    Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                    Information = 0;
                }

                End(Instance, Transfer, Status, Information);
                return true;
            }

            private void EndExpiredPolls(BinaryEmulator Instance)
            {
                long Tick = Instance.EmulatedTickCount64;
                long Next = -1;
                for (int i = 0; i < Polls.Count; i++)
                {
                    PendingPoll Poll = Polls[i];
                    if (BinaryEmulator.IsDeadlineExpired(Poll.Deadline, Tick))
                    {
                        Polls.RemoveAt(i--);
                        End(Instance, Poll, NTSTATUS.STATUS_TIMEOUT);
                        continue;
                    }

                    if (Poll.Deadline >= 0 && (Next < 0 || Poll.Deadline < Next))
                        Next = Poll.Deadline;
                }

                EarliestDeadline = Next;
            }

            internal void ReplaceExclusive(BinaryEmulator Instance, AfdDevice Endpoint)
            {
                for (int i = 0; i < Polls.Count; i++)
                {
                    PendingPoll Replaced = Polls[i];
                    if (!Replaced.Exclusive || !Replaced.Names(Endpoint))
                        continue;

                    Polls.RemoveAt(i);
                    End(Instance, Replaced, NTSTATUS.STATUS_SUCCESS);
                    return;
                }
            }

            // AfdCleanupCore
            internal void EndpointClosed(BinaryEmulator Instance, AfdDevice Endpoint)
            {
                bool Datagram = Endpoint._socket?.SocketType == SocketType.Dgram;
                for (int i = 0; i < Polls.Count; i++)
                {
                    PendingPoll Poll = Polls[i];
                    if (!Poll.Names(Endpoint))
                        continue;

                    Polls.RemoveAt(i--);
                    TryEndReady(Instance, Poll, Endpoint);
                }

                for (int i = 0; i < Transfers.Count; i++)
                {
                    PendingTransfer Transfer = Transfers[i];
                    if (!ReferenceEquals(Transfer.Endpoint, Endpoint))
                        continue;

                    Transfers.RemoveAt(i--);
                    NTSTATUS Status = Datagram ? NTSTATUS.STATUS_CANCELLED :
                        Transfer.Posted ? NTSTATUS.STATUS_CONNECTION_ABORTED : NTSTATUS.STATUS_LOCAL_DISCONNECT;
                    End(Instance, Transfer, Status, 0);
                }

                for (int i = 0; i < Accepts.Count; i++)
                {
                    PendingAccept Accept = Accepts[i];
                    if (!ReferenceEquals(Accept.WaitsOn, Endpoint) && !ReferenceEquals(Accept.Target, Endpoint))
                        continue;

                    Accepts.RemoveAt(i--);
                    End(Instance, Accept, NTSTATUS.STATUS_CANCELLED, 0);
                }

                Endpoint.ReleaseSocket(Instance);
            }

            internal void ReleaseSocket(AfdDevice Endpoint, BrovanSocket Socket)
            {
                if (Watcher != null)
                    Watcher.Release(Endpoint, Socket);
                else
                    Socket.Dispose();
            }

            internal int Cancel(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, int ThreadId)
            {
                int Cancelled = 0;
                for (int i = 0; i < Polls.Count; i++)
                {
                    PendingPoll Poll = Polls[i];
                    if (!Matches(in Poll.Io, File, IoStatusBlock, ThreadId))
                        continue;

                    Polls.RemoveAt(i--);
                    End(Instance, Poll, NTSTATUS.STATUS_CANCELLED);
                    Cancelled++;
                }

                for (int i = 0; i < Transfers.Count; i++)
                {
                    PendingTransfer Transfer = Transfers[i];
                    if (!Matches(in Transfer.Io, File, IoStatusBlock, ThreadId))
                        continue;

                    Transfers.RemoveAt(i--);
                    End(Instance, Transfer, NTSTATUS.STATUS_CANCELLED, 0);
                    Cancelled++;
                }

                for (int i = 0; i < Accepts.Count; i++)
                {
                    PendingAccept Accept = Accepts[i];
                    if (!Matches(in Accept.Io, File, IoStatusBlock, ThreadId))
                        continue;

                    Accepts.RemoveAt(i--);
                    End(Instance, Accept, NTSTATUS.STATUS_CANCELLED, 0);
                    Cancelled++;
                }

                return Cancelled;
            }

            private static bool Matches(in WinPendingIo Io, WinFile File, ulong IoStatusBlock, int ThreadId) =>
                ReferenceEquals(Io.File, File) && (IoStatusBlock == 0 || Io.IoStatusBlock == IoStatusBlock) && (ThreadId < 0 || Io.ThreadId == ThreadId);

            internal void CancelThread(BinaryEmulator Instance, int ThreadId)
            {
                for (int i = 0; i < Polls.Count; i++)
                {
                    PendingPoll Poll = Polls[i];
                    if (Poll.Io.ThreadId != ThreadId || WinSysHelper.CompletesToPort(in Poll.Io))
                        continue;

                    Polls.RemoveAt(i--);
                    End(Instance, Poll, NTSTATUS.STATUS_CANCELLED);
                }

                for (int i = 0; i < Transfers.Count; i++)
                {
                    PendingTransfer Transfer = Transfers[i];
                    if (Transfer.Io.ThreadId != ThreadId || WinSysHelper.CompletesToPort(in Transfer.Io))
                        continue;

                    Transfers.RemoveAt(i--);
                    End(Instance, Transfer, NTSTATUS.STATUS_CANCELLED, 0);
                }

                for (int i = 0; i < Accepts.Count; i++)
                {
                    PendingAccept Accept = Accepts[i];
                    if (Accept.Io.ThreadId != ThreadId || WinSysHelper.CompletesToPort(in Accept.Io))
                        continue;

                    Accepts.RemoveAt(i--);
                    End(Instance, Accept, NTSTATUS.STATUS_CANCELLED, 0);
                }
            }

            public void Dispose() => Watcher?.Dispose();

            private static bool TryEndReady(BinaryEmulator Instance, PendingPoll Poll, AfdDevice? Closing)
            {
                int PointerSize = Instance.WinHelper.PointerSize;
                Span<byte> Output = Instance.WinHelper.Shared.GetSpan((ulong)PollOutputBytes(Poll.Entries.Length, PointerSize));
                int Ready = FillPollOutput(Output, Poll.Entries, Closing, PointerSize);
                if (Ready == 0)
                    return false;

                End(Instance, Poll, NTSTATUS.STATUS_SUCCESS, Output, Ready);
                return true;
            }

            private static void End(BinaryEmulator Instance, PendingPoll Poll, NTSTATUS Status) =>
                End(Instance, Poll, Status, Instance.WinHelper.Shared.GetSpan(PollHeaderSize), 0);

            // AFD sets Information on an error too, but copies no output.
            private static void End(BinaryEmulator Instance, PendingPoll Poll, NTSTATUS Status, Span<byte> Output, int Ready)
            {
                int Length = PollOutputBytes(Ready, Instance.WinHelper.PointerSize);
                if (((uint)Status >> 30) != 3 && Instance.WinHelper.IsPendingIoLive(in Poll.Io))
                {
                    WritePollHeader(Output, Poll.Timeout, (uint)Ready, Poll.ExclusiveField);
                    if (!Instance.WriteMemory(Poll.Output, Output.Slice(0, Length)))
                    {
                        Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
                        Length = 0;
                    }
                }

                Poll.Status = Status;
                Poll.Completed = true;
                Instance.WinHelper.CompletePendingIo(in Poll.Io, Status, (ulong)Length);
                Instance.WakeSignal.Bump();
            }

            private static void End(BinaryEmulator Instance, PendingTransfer Transfer, NTSTATUS Status, ulong Information)
            {
                if (((uint)Status >> 30) == 3)
                    Information = 0;

                Transfer.Status = Status;
                Transfer.Completed = true;
                Transfer.Buffers.Release();
                Instance.WinHelper.CompletePendingIo(in Transfer.Io, Status, Information);
                Instance.WakeSignal.Bump();
            }

            private static void End(BinaryEmulator Instance, PendingAccept Accept, NTSTATUS Status, ulong Information)
            {
                if (((uint)Status >> 30) == 3)
                    Information = 0;

                Accept.Target._superAcceptTarget = false;
                Accept.Status = Status;
                Accept.Completed = true;
                Instance.WinHelper.CompletePendingIo(in Accept.Io, Status, Information);
                Instance.WakeSignal.Bump();
            }
        }

        // Host thread. Touch only host sockets, this state and the wake counter.
        internal sealed class HostSocketWatcher : IDisposable
        {
            internal const byte WatchRead = 1;
            internal const byte WatchWrite = 2;
            internal const byte WatchError = 4;

            private readonly object Gate = new();
            private readonly WakeSignal Wake;
            private readonly Dictionary<AfdDevice, (BrovanSocket Socket, byte Modes)> Armed = new();
            private readonly Dictionary<Socket, AfdDevice> Selecting = new();
            private readonly List<BrovanSocket> Orphans = new();
            private readonly List<AfdDevice> Ready = new();
            private volatile bool ReadyPending;
            private bool InSelect;
            private bool Stopping;
            private volatile bool StartFailed;
            private Socket? WakeReceiver;
            private Socket? WakeSender;
            private Thread? Worker;

            private readonly List<Socket> ReadList = new();
            private readonly List<Socket> WriteList = new();
            private readonly List<Socket> ErrorList = new();
            private readonly List<BrovanSocket> Closing = new();
            private readonly byte[] WakeBytes = new byte[64];

            internal HostSocketWatcher(WakeSignal Wake) => this.Wake = Wake;

            internal bool HasReady => ReadyPending;

            // A datagram to itself wakes Select when the set changes.
            internal bool TryStart()
            {
                if (StartFailed || Stopping)
                    return false;

                if (Worker != null)
                    return true;

                try
                {
                    WakeReceiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { Blocking = false };
                    WakeReceiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                    WakeSender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { Blocking = false };
                    WakeSender.Connect(WakeReceiver.LocalEndPoint!);
                }
                catch (SocketException Ex)
                {
                    Utils.LogError($"AFD socket watcher has no loopback wake socket: {Ex.Message}");
                    WakeReceiver?.Dispose();
                    WakeSender?.Dispose();
                    WakeReceiver = null;
                    WakeSender = null;
                    StartFailed = true;
                    return false;
                }

                Worker = new Thread(Run) { IsBackground = true, Name = "AFD socket watcher" };
                Worker.Start();
                return true;
            }

            internal void Watch(AfdDevice Endpoint, BrovanSocket? Socket, byte Modes) => Arm(Endpoint, Socket, Modes, false);

            internal void WatchAlso(AfdDevice Endpoint, BrovanSocket? Socket, byte Modes) => Arm(Endpoint, Socket, Modes, true);

            private void Arm(AfdDevice Endpoint, BrovanSocket? Socket, byte Modes, bool Merge)
            {
                bool Signal;
                lock (Gate)
                {
                    bool Known = Armed.TryGetValue(Endpoint, out (BrovanSocket Socket, byte Modes) Current) && ReferenceEquals(Current.Socket, Socket);
                    if (Merge && Known)
                        Modes |= Current.Modes;

                    if (Socket == null || Modes == 0)
                    {
                        if (!Merge)
                            Armed.Remove(Endpoint);

                        return;
                    }

                    if (Known && Current.Modes == Modes)
                        return;

                    Armed[Endpoint] = (Socket, Modes);
                    Signal = InSelect;
                }

                if (Signal)
                    SignalWorker();
            }

            internal void Release(AfdDevice Endpoint, BrovanSocket Socket)
            {
                bool Deferred;
                lock (Gate)
                {
                    if (Armed.TryGetValue(Endpoint, out (BrovanSocket Socket, byte Modes) Current) && ReferenceEquals(Current.Socket, Socket))
                        Armed.Remove(Endpoint);

                    Deferred = InSelect && Selecting.ContainsKey(Socket.Selectable);
                    if (Deferred)
                        Orphans.Add(Socket);
                }

                if (Deferred)
                    SignalWorker();
                else
                    Socket.Dispose();
            }

            internal void TakeReady(List<AfdDevice> Into)
            {
                lock (Gate)
                {
                    Into.AddRange(Ready);
                    Ready.Clear();
                    ReadyPending = false;
                }
            }

            private void SignalWorker() => WakeSender!.Send(WakeBytes.AsSpan(0, 1), SocketFlags.None, out _);

            private void Run()
            {
                while (true)
                {
                    lock (Gate)
                    {
                        if (Stopping)
                            break;

                        ReadList.Clear();
                        WriteList.Clear();
                        ErrorList.Clear();
                        Selecting.Clear();
                        ReadList.Add(WakeReceiver!);
                        foreach (KeyValuePair<AfdDevice, (BrovanSocket Socket, byte Modes)> Watched in Armed)
                        {
                            Socket Host = Watched.Value.Socket.Selectable;
                            Selecting[Host] = Watched.Key;
                            if ((Watched.Value.Modes & WatchRead) != 0)
                                ReadList.Add(Host);
                            if ((Watched.Value.Modes & WatchWrite) != 0)
                                WriteList.Add(Host);
                            if ((Watched.Value.Modes & WatchError) != 0)
                                ErrorList.Add(Host);
                        }

                        InSelect = true;
                    }

                    bool Failed = false;
                    try
                    {
                        Socket.Select(ReadList, WriteList, ErrorList, -1);
                    }
                    catch (Exception Ex) when (Ex is SocketException or ObjectDisposedException)
                    {
                        Utils.LogError($"AFD socket watcher: Select failed: {Ex.Message}");
                        Failed = true;
                    }

                    bool Published;
                    lock (Gate)
                    {
                        InSelect = false;
                        int Before = Ready.Count;
                        if (Failed && Armed.Count == 0)
                        {
                            // Only the wake socket was in the set, so it is broken.
                            Utils.LogError("AFD socket watcher stopped.");
                            StartFailed = true;
                            Closing.AddRange(Orphans);
                            Orphans.Clear();
                            break;
                        }

                        if (Failed)
                        {
                            foreach (AfdDevice Endpoint in Armed.Keys)
                                Ready.Add(Endpoint);

                            Armed.Clear();
                        }
                        else
                        {
                            PublishReady(ReadList);
                            PublishReady(WriteList);
                            PublishReady(ErrorList);
                        }

                        Published = Ready.Count != Before;
                        if (Published)
                            ReadyPending = true;

                        Closing.AddRange(Orphans);
                        Orphans.Clear();
                    }

                    if (!Failed && ReadList.Contains(WakeReceiver!))
                    {
                        while (WakeReceiver!.Receive(WakeBytes, 0, WakeBytes.Length, SocketFlags.None, out SocketError Error) > 0 && Error == SocketError.Success)
                        {
                        }
                    }

                    for (int i = 0; i < Closing.Count; i++)
                        Closing[i].Dispose();

                    Closing.Clear();

                    if (Published)
                        Wake.Bump();
                }

                for (int i = 0; i < Closing.Count; i++)
                    Closing[i].Dispose();

                Closing.Clear();
            }

            private void PublishReady(List<Socket> Selected)
            {
                for (int i = 0; i < Selected.Count; i++)
                {
                    if (!Selecting.TryGetValue(Selected[i], out AfdDevice? Endpoint))
                        continue;

                    if (Armed.TryGetValue(Endpoint, out (BrovanSocket Socket, byte Modes) Current) && ReferenceEquals(Current.Socket.Selectable, Selected[i]))
                    {
                        Armed.Remove(Endpoint);
                        Ready.Add(Endpoint);
                    }
                }
            }

            // A worker that does not stop may still be inside Select, so its sockets stay open.
            public void Dispose()
            {
                Thread? Running;
                lock (Gate)
                {
                    Stopping = true;
                    Running = Worker;
                }

                if (Running == null)
                    return;

                SignalWorker();
                if (!Running.Join(1000))
                {
                    Utils.LogError("AFD socket watcher did not stop.");
                    return;
                }

                for (int i = 0; i < Orphans.Count; i++)
                    Orphans[i].Dispose();

                Orphans.Clear();
                WakeReceiver!.Dispose();
                WakeSender!.Dispose();
            }
        }

        internal sealed class HostConnects
        {
            private readonly ConcurrentQueue<HostConnect> Finished = new();

            internal int InFlight;

            internal bool HasFinished => !Finished.IsEmpty;

            internal void Publish(HostConnect Connect) => Finished.Enqueue(Connect);

            internal void CompleteFinished(BinaryEmulator Instance)
            {
                while (Finished.TryDequeue(out HostConnect? Connect))
                {
                    InFlight--;
                    Connect.Complete(Instance);
                }
            }
        }

        internal sealed class HostConnect
        {
            private readonly HostConnects Owner;
            private readonly WakeSignal Wake;
            private readonly AfdDevice Endpoint;
            private readonly WinPendingIo Io;
            private readonly ulong StatusBuffer;
            private BrovanSocket? Socket;
            private SocketAsyncEventArgs? Args;
            private SocketError Result;
            private byte[]? SendData;
            private int SendLength;
            private bool SendDataPooled;
            private int Sent;

            // AfdConnect writes its status at the start of the output buffer. ConnectEx puts its send data there.
            internal HostConnect(BinaryEmulator Instance, AfdDevice Endpoint, in DeviceData Data, bool WritesStatus)
            {
                Owner = Instance.WinHelper.AfdConnects;
                Wake = Instance.WakeSignal;
                this.Endpoint = Endpoint;
                Io = new WinPendingIo(in Data, Instance.CurrentThreadId, Instance.WinHelper.GetEventByHandle(Data.EventHandle, AccessMask.GiveTemp));
                StatusBuffer = WritesStatus ? Data.UserBuffer : 0;
            }

            // AFD copies the send data when the request starts.
            internal NTSTATUS CopySendData(in DeviceData Data, BinaryEmulator Instance)
            {
                if (Data.OutputLength == 0)
                    return NTSTATUS.STATUS_SUCCESS;

                SendLength = (int)Data.OutputLength;
                SendDataPooled = Data.OutputLength <= MemoryBudget.PooledIoBytes;
                SendData = SendDataPooled ? ArrayPool<byte>.Shared.Rent(SendLength) : new byte[SendLength];

                if (Instance.ReadMemory(Data.UserBuffer, SendData.AsSpan(0, SendLength)))
                    return NTSTATUS.STATUS_SUCCESS;

                ReleaseSendData();
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            internal void ReleaseSendData()
            {
                if (SendData != null && SendDataPooled)
                    ArrayPool<byte>.Shared.Return(SendData);

                SendData = null;
                SendLength = 0;
            }

            internal NTSTATUS Start(BrovanSocket Socket, IPEndPoint Remote)
            {
                this.Socket = Socket;

                if (Endpoint.HasNoPathTo(Socket, Remote))
                {
                    Begin();
                    Result = SocketError.AddressNotAvailable;
                    Finish();
                    return NTSTATUS.STATUS_PENDING;
                }

                Args = new SocketAsyncEventArgs { RemoteEndPoint = Remote, UserToken = this };
                Args.Completed += OnHostCompleted;

                bool Pending;
                try
                {
                    Pending = Socket.ConnectAsync(Args);
                }
                catch (Exception Ex)
                {
                    Args.Dispose();
                    ReleaseSendData();
                    return Ex is SocketException SocketEx ? MapSocketError(SocketEx.SocketErrorCode) : NTSTATUS.STATUS_UNSUCCESSFUL;
                }

                Begin();
                if (!Pending)
                    OnHostCompleted(null, Args);

                return NTSTATUS.STATUS_PENDING;
            }

            private void Begin()
            {
                Endpoint._connectPending = true;
                Endpoint._connectFailure = NTSTATUS.STATUS_SUCCESS;
                Owner.InFlight++;
            }

            // Host thread. Touch only the host socket, the queue and the wake counter.
            private static void OnHostCompleted(object? Sender, SocketAsyncEventArgs Completed)
            {
                HostConnect Connect = (HostConnect)Completed.UserToken!;
                if (!Connect.TrySendMore(Completed))
                    Connect.Finish();
            }

            // AFD completes ConnectEx once its send data is buffered on the new connection.
            private bool TrySendMore(SocketAsyncEventArgs Completed)
            {
                while (true)
                {
                    Result = Completed.SocketError;
                    if (Result != SocketError.Success)
                        return false;

                    if (Completed.LastOperation == SocketAsyncOperation.Send)
                    {
                        if (Completed.BytesTransferred <= 0)
                        {
                            Result = SocketError.ConnectionAborted;
                            return false;
                        }

                        Sent += Completed.BytesTransferred;
                    }

                    if (Sent >= SendLength)
                        return false;

                    try
                    {
                        Completed.SetBuffer(SendData, Sent, SendLength - Sent);
                        if (Socket!.SendAsync(Completed))
                            return true;
                    }
                    catch (ObjectDisposedException)
                    {
                        Result = SocketError.OperationAborted;
                        return false;
                    }
                    catch (Exception Ex)
                    {
                        Utils.LogError($"AFD connect send failed: {Ex}");
                        Result = SocketError.OperationAborted;
                        return false;
                    }
                }
            }

            private void Finish()
            {
                Owner.Publish(this);
                Wake.Bump();
            }

            internal void Complete(BinaryEmulator Instance)
            {
                NTSTATUS Status = MapSocketError(Result);
                Endpoint._connectPending = false;
                Endpoint._connectFailure = (int)Status < 0 ? Status : NTSTATUS.STATUS_SUCCESS;
                if ((int)Status >= 0)
                    Endpoint._connectedAt = Instance.GetEmulatedSystemTimeFileTimeUtc();

                if (StatusBuffer != 0 && Instance.WinHelper.IsPendingIoLive(in Io))
                    Instance.WinHelper.WriteUInt32(StatusBuffer, (uint)Status);

                if (Sent > 0 && Socket != null)
                    NetworkTrafficPcapCapture.RecordOutbound(Socket, SendData.AsSpan(0, Sent));

                Instance.WinHelper.CompletePendingIo(in Io, Status, (int)Status < 0 ? 0ul : (ulong)Sent);
                ReleaseSendData();
                Args?.Dispose();
                Instance.WinHelper.AfdRequests.Recheck(Instance, Endpoint);
            }
        }
    }

    internal sealed class AfdEndpointDevice : IWinDevice
    {
        public string DeviceName => "\\Device\\Afd\\Endpoint";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            AfdDevice Device = new AfdDevice(EaBuffer);
            InternalPath = DevicePath + "\\" + Guid.NewGuid().ToString("N");
            Handler = Device.Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal sealed class AfdAsyncConnectHelperDevice : IWinDevice
    {
        public string DeviceName => "\\Device\\Afd\\AsyncConnectHlp";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = AfdDevice.HandleConnectHelper;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
