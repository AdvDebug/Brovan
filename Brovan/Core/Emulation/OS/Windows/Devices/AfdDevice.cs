using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Brovan.Core.Emulation;
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
        private const int AFD_GET_ADDRESS = 11;
        private const int AFD_EVENT_SELECT = 33;
        private const int AFD_ENUM_NETWORK_EVENTS = 34;
        private const int AFD_ROUTING_INTERFACE_QUERY = 42;
        private const int AFD_ADDRESS_LIST_QUERY = 44;
        private const int AFD_TRANSPORT_IOCTL = 47;

        private const uint MethodNeither = 3;
        private const uint IoctlAfdConnect = ((uint)FsctlAfdBase << 12) | ((uint)AFD_CONNECT << 2) | MethodNeither;

        private const uint AFD_POLL_RECEIVE = 1u << 0;
        private const uint AFD_POLL_SEND = 1u << 2;
        private const uint AFD_POLL_DISCONNECT = 1u << 3;
        private const uint AFD_POLL_ABORT = 1u << 4;
        private const uint AFD_POLL_LOCAL_CLOSE = 1u << 5;
        private const uint AFD_POLL_CONNECT = 1u << 6;
        private const uint AFD_POLL_ACCEPT = 1u << 7;
        private const uint AFD_POLL_CONNECT_FAIL = 1u << 8;

        private const uint PollReadEvents = AFD_POLL_RECEIVE | AFD_POLL_DISCONNECT | AFD_POLL_ACCEPT;
        private const uint PollWriteEvents = AFD_POLL_SEND | AFD_POLL_CONNECT;
        private const uint PollErrorEvents = AFD_POLL_CONNECT_FAIL | AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE;

        private const int DefaultIoTimeoutMs = 5000;
        private const int PollRetrySliceMs = 1;

        private BrovanSocket? _socket;
        private NetworkAccessPolicy _policy;
        private bool IsListening;
        private bool _connectPending;
        private NTSTATUS _connectFailure;

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

        private static int DecodeBase(uint Ioctl) => (int)((Ioctl >> 12) & 0xFFFFF);
        private static int DecodeRequest(uint Ioctl) => (int)((Ioctl >> 2) & 0x03FF);

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

            _socket = new BrovanSocket(Family, Type, Protocol, _policy);
            _socket.SendTimeout = DefaultIoTimeoutMs;
            _socket.ReceiveTimeout = DefaultIoTimeoutMs;

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

        private static (uint Length, ulong BufferPtr)? ReadWsabuf(BinaryEmulator Emulator, ulong WsaBufPtr)
        {
            if (WsaBufPtr == 0)
                return null;

            if (Emulator._binary.Architecture == BinaryArchitecture.x64)
            {
                if (!Emulator.IsRegionMapped(WsaBufPtr, 16))
                    return null;

                uint Length = Emulator._emulator.ReadMemoryUInt(WsaBufPtr);
                ulong BufferPtr = Emulator._emulator.ReadMemoryULong(WsaBufPtr + 8);
                return (Length, BufferPtr);
            }

            if (!Emulator.IsRegionMapped(WsaBufPtr, 8))
                return null;

            uint Length32 = Emulator._emulator.ReadMemoryUInt(WsaBufPtr);
            ulong BufferPtr32 = Emulator._emulator.ReadMemoryUInt(WsaBufPtr + 4);
            return (Length32, BufferPtr32);
        }

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

                if ((Requested & AFD_POLL_LOCAL_CLOSE) != 0)
                    Triggered |= AFD_POLL_LOCAL_CLOSE;
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
                IsListening = true;
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch
            {
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
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

            TargetEndpoint._socket?.Dispose();
            TargetEndpoint._socket = Accepted;
            TargetEndpoint.IsListening = false;

            _PendingAccepted.Remove(Sequence);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS IoctlSend(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

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

            if (BufferCount > 1)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            var WsaBuf = ReadWsabuf(Instance, WsaBufArrayPtr);
            if (WsaBuf == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Length = WsaBuf.Value.Length;
            ulong BufferPtr = WsaBuf.Value.BufferPtr;

            if (Length == 0 || BufferPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BufferPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Length > int.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] Payload = Instance.WinHelper.Shared.GetBuffer(Length);
            if (!Instance._emulator.ReadMemory(BufferPtr, Payload.AsSpan(0, (int)Length), Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!IsSocketRemoteAllowed(Instance, _socket, true))
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            try
            {
                int Sent = _socket.Send(Payload, 0, (int)Length, SocketFlags.None);
                if (Sent > 0)
                    NetworkTrafficPcapCapture.RecordOutbound(_socket, Payload.AsSpan(0, Sent));

                Data.Information = (ulong)Sent;
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        private NTSTATUS IoctlReceive(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

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

            if (BufferCount > 1)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            var WsaBuf = ReadWsabuf(Instance, WsaBufArrayPtr);
            if (WsaBuf == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Length = WsaBuf.Value.Length;
            ulong BufferPtr = WsaBuf.Value.BufferPtr;

            if (Length == 0 || BufferPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BufferPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Length > int.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            byte[] RecvBuffer = Instance.WinHelper.Shared.GetBuffer(Length);

            if (!IsSocketRemoteAllowed(Instance, _socket, true))
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            try
            {
                int Received = _socket.Receive(RecvBuffer, 0, (int)Length, SocketFlags.None);

                if (Received > 0)
                {
                    Instance.WriteMemory(BufferPtr, RecvBuffer.AsSpan(0, Received));
                    NetworkTrafficPcapCapture.RecordInbound(_socket, RecvBuffer.AsSpan(0, Received));
                }

                Data.Information = (ulong)Math.Max(0, Received);
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch (SocketException Se) when (Se.SocketErrorCode == SocketError.TimedOut)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_TIMEOUT;
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
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
            if (Data.InputBuffer == null || Data.OutputBuffer == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int HeaderSize = 16;
            uint InputLength = GuestInputLength(in Data);
            if (InputLength < HeaderSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Count = ReadU32(Data.InputBuffer, 8);
            if (Count == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int EntrySize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 16 : 12;
            long Needed = HeaderSize + (long)Count * EntrySize;

            if (InputLength < Needed || GuestOutputLength(in Data) < InputLength)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int OutIndex = 0;
            Buffer.BlockCopy(Data.InputBuffer, 0, Data.OutputBuffer, 0, HeaderSize);
            bool Waiting = Instance.WinHelper.IsPipeWaitActive(Data.FileHandle);

            for (int i = 0; i < Count; i++)
            {
                int EntryOffset = HeaderSize + i * EntrySize;

                ulong Handle = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? BitConverter.ToUInt64(Data.InputBuffer, EntryOffset)
                    : BitConverter.ToUInt32(Data.InputBuffer, EntryOffset);

                uint Requested = ReadU32(Data.InputBuffer, EntryOffset + (Instance._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4));

                WinFile? File = Instance.WinHelper.GetFileByHandle(Handle, AccessMask.GiveTemp);
                NTSTATUS EntryStatus = NTSTATUS.STATUS_SUCCESS;
                uint Triggered;

                if (File?.Handler?.Target is not AfdDevice EndpointDevice)
                {
                    // NT ends a waiting poll when one of its endpoints closes.
                    if (!Waiting)
                        return NTSTATUS.STATUS_INVALID_HANDLE;

                    Triggered = AFD_POLL_LOCAL_CLOSE;
                }
                else if (EndpointDevice._socket == null || EndpointDevice._connectPending)
                {
                    continue;
                }
                else if ((int)EndpointDevice._connectFailure < 0 && !EndpointDevice._socket.Connected)
                {
                    Triggered = Requested & AFD_POLL_CONNECT_FAIL;
                    EntryStatus = EndpointDevice._connectFailure;
                }
                else
                {
                    BrovanSocket HostSocket = EndpointDevice._socket;
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

                    Triggered = MapPollEventsToTriggered(Requested, ReadReady, WriteReady, ErrorReady, EndpointDevice.IsListening);
                }

                if (Triggered == 0)
                    continue;

                int OutEntryOffset = HeaderSize + OutIndex * EntrySize;

                if (Instance._binary.Architecture == BinaryArchitecture.x64)
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset, 8), Handle);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 8, 4), Triggered);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 12, 4), (uint)EntryStatus);
                }
                else
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset, 4), (uint)Handle);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 4, 4), Triggered);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 8, 4), (uint)EntryStatus);
                }

                OutIndex++;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(8, 4), (uint)OutIndex);

            long Timeout = BinaryPrimitives.ReadInt64LittleEndian(Data.InputBuffer.AsSpan(0, 8));
            bool Overlapped = Data.ApcContext != 0 || Data.ApcRoutine != 0;

            // Information stays 0 while pending, so the retry reads the input unchanged.
            if (OutIndex == 0 && Timeout != 0 && !Overlapped &&
                Instance.WinHelper.TryContinuePipeWait(Data.FileHandle, PollTimeoutMs(Instance, Timeout), PollRetrySliceMs))
                return NTSTATUS.STATUS_PENDING;

            Instance.WinHelper.ClearPipeWait();
            Data.Information = (ulong)(HeaderSize + OutIndex * EntrySize);

            return OutIndex == 0 && Timeout != 0 ? NTSTATUS.STATUS_TIMEOUT : NTSTATUS.STATUS_SUCCESS;
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

            if (DecodeBase(Ioctl) != FsctlAfdBase)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

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
                    AFD_SEND => IoctlSend(ref Data, Instance),
                    AFD_RECEIVE => IoctlReceive(ref Data, Instance),
                    AFD_GET_ADDRESS => IoctlGetAddress(ref Data),
                    AFD_POLL => IoctlPoll(ref Data, Instance),
                    AFD_EVENT_SELECT => NTSTATUS.STATUS_SUCCESS,
                    AFD_ENUM_NETWORK_EVENTS => NTSTATUS.STATUS_SUCCESS,
                    AFD_RECEIVE_DATAGRAM => Policy.Mode == NetworkAccessMode.Full ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NETWORK_UNREACHABLE,
                    AFD_SEND_DATAGRAM => Policy.Mode == NetworkAccessMode.Full ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NETWORK_UNREACHABLE,
                    AFD_ROUTING_INTERFACE_QUERY or AFD_ADDRESS_LIST_QUERY or AFD_TRANSPORT_IOCTL => ReplyZeroed(ref Data),
                    _ => NTSTATUS.STATUS_SUCCESS
                };
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
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
                NTSTATUS Rebound = Endpoint.RebindAfterFailedConnect();
                if (Rebound != NTSTATUS.STATUS_SUCCESS)
                    return Rebound;

                Socket = Endpoint._socket!;
            }

            return new HostConnect(Instance, Endpoint, in Data).Start(Socket, Remote);
        }

        // A host can replace a socket that failed to connect with an unbound one. AFD keeps the endpoint bound.
        private NTSTATUS RebindAfterFailedConnect()
        {
            try
            {
                EndPoint? Local = _socket?.LocalEndPoint;
                if (Local == null)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                _socket!.Dispose();
                _socket = null;
                EnsureSocket();
                _socket!.Bind(Local);
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch (Exception Ex)
            {
                return Ex is SocketException SocketEx ? MapConnectError(SocketEx.SocketErrorCode) : NTSTATUS.STATUS_UNSUCCESSFUL;
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

        private static NTSTATUS MapConnectError(SocketError Error) => Error switch
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
            _ => NTSTATUS.STATUS_UNSUCCESSFUL
        };

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
            private readonly ulong UserBuffer;
            private SocketAsyncEventArgs? Args;
            private SocketError Result;

            internal HostConnect(BinaryEmulator Instance, AfdDevice Endpoint, in DeviceData Data)
            {
                Owner = Instance.WinHelper.AfdConnects;
                Wake = Instance.WakeSignal;
                this.Endpoint = Endpoint;
                Io = new WinPendingIo(in Data, Instance.CurrentThreadId, Instance.WinHelper.GetEventByHandle(Data.EventHandle, AccessMask.GiveTemp));
                UserBuffer = Data.UserBuffer;
            }

            internal NTSTATUS Start(BrovanSocket Socket, IPEndPoint Remote)
            {
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
                    return Ex is SocketException SocketEx ? MapConnectError(SocketEx.SocketErrorCode) : NTSTATUS.STATUS_UNSUCCESSFUL;
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

            // Host thread. Touch only the queue and the wake counter.
            private static void OnHostCompleted(object? Sender, SocketAsyncEventArgs Completed)
            {
                HostConnect Connect = (HostConnect)Completed.UserToken!;
                Connect.Result = Completed.SocketError;
                Connect.Finish();
            }

            private void Finish()
            {
                Owner.Publish(this);
                Wake.Bump();
            }

            internal void Complete(BinaryEmulator Instance)
            {
                NTSTATUS Status = MapConnectError(Result);
                Endpoint._connectPending = false;
                Endpoint._connectFailure = (int)Status < 0 ? Status : NTSTATUS.STATUS_SUCCESS;

                // AFD writes the status to the start of the output buffer.
                if (UserBuffer != 0 && Instance.WinHelper.IsPendingIoLive(in Io))
                    Instance.WinHelper.WriteUInt32(UserBuffer, (uint)Status);

                Instance.WinHelper.CompletePendingIo(in Io, Status, 0);
                Args?.Dispose();
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
