using System;
using System.Buffers.Binary;
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

        private const uint AFD_POLL_RECEIVE = 1u << 0;
        private const uint AFD_POLL_SEND = 1u << 2;
        private const uint AFD_POLL_DISCONNECT = 1u << 3;
        private const uint AFD_POLL_ABORT = 1u << 4;
        private const uint AFD_POLL_LOCAL_CLOSE = 1u << 5;
        private const uint AFD_POLL_CONNECT = 1u << 6;
        private const uint AFD_POLL_ACCEPT = 1u << 7;
        private const uint AFD_POLL_CONNECT_FAIL = 1u << 8;

        private const int DefaultConnectTimeoutMs = 5000;
        private const int DefaultIoTimeoutMs = 5000;
        private const int DefaultAcceptTimeoutMs = 10000;

        private Socket? _socket;
        private bool IsListening;

        private readonly Dictionary<int, Socket> _PendingAccepted = new();
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

        private static SocketType TranslateWinType(int WinType)
        {
            return WinType switch
            {
                1 => SocketType.Stream,
                2 => SocketType.Dgram,
                3 => SocketType.Raw,
                4 => SocketType.Rdm,
                _ => SocketType.Unknown
            };
        }

        private static ProtocolType TranslateWinProtocol(int WinProtocol)
        {
            return WinProtocol switch
            {
                6 => ProtocolType.Tcp,
                17 => ProtocolType.Udp,
                255 => ProtocolType.Raw,
                _ => ProtocolType.Unspecified
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

            if (Type == SocketType.Unknown)
                Type = SocketType.Stream;

            _socket = new Socket(Family, Type, Protocol);
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

        private static IPEndPoint? ParseSockaddr(byte[] Data, int Offset)
        {
            if (Data.Length < Offset + 4)
                return null;

            short Family = BitConverter.ToInt16(Data, Offset + 0);

            if (Family == 2)
            {
                if (Data.Length < Offset + 16)
                    return null;

                ushort PortNetwork = BitConverter.ToUInt16(Data, Offset + 2);
                ushort Port = Swap16(PortNetwork);

                return new IPEndPoint(new IPAddress(Data.AsSpan(Offset + 4, 4)), Port);
            }

            if (Family == 23)
            {
                if (Data.Length < Offset + 28)
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

        private bool ConnectWithTimeout(EndPoint Remote, int TimeoutMs)
        {
            EnsureSocket();
            if (_socket == null)
                return false;

            try
            {
                IAsyncResult Ar = _socket.BeginConnect(Remote, null, null);

                bool Ok = Ar.AsyncWaitHandle.WaitOne(TimeoutMs);
                if (!Ok)
                {
                    try { _socket.Close(); } catch { }
                    return false;
                }

                _socket.EndConnect(Ar);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private Socket? AcceptWithTimeout(int TimeoutMs, out EndPoint? Remote)
        {
            Remote = null;
            EnsureSocket();
            if (_socket == null)
                return null;

            try
            {
                if (!_socket.Poll(TimeoutMs * 1000, SelectMode.SelectRead))
                    return null;

                Socket Accepted = _socket.Accept();
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

        private static bool IsSocketRemoteAllowed(BinaryEmulator Instance, Socket Socket, bool RequireKnownRemote)
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

            if (Data.InputBuffer == null || Data.InputBuffer.Length < 4 + 16)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            IPEndPoint? IpEndPoint = ParseSockaddr(Data.InputBuffer, 4);
            if (IpEndPoint == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!IsEndpointAllowed(Instance, IpEndPoint))
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

        private NTSTATUS IoctlConnect(ref DeviceData Data, BinaryEmulator Instance)
        {
            EnsureSocket();
            if (_socket == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (Data.InputBuffer == null || Data.InputBuffer.Length < 24 + 16)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            IPEndPoint? IpEndPoint = ParseSockaddr(Data.InputBuffer, 24);
            if (IpEndPoint == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!IsEndpointAllowed(Instance, IpEndPoint))
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            bool Ok = ConnectWithTimeout(IpEndPoint, DefaultConnectTimeoutMs);
            return Ok ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_UNSUCCESSFUL;
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

            if (Data.InputBuffer == null || Data.InputBuffer.Length < 8)
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

            if (Data.OutputBuffer == null || Data.OutputBuffer.Length < 20)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Socket? Accepted = AcceptWithTimeout(DefaultAcceptTimeoutMs, out EndPoint? Remote);
            if (Accepted == null)
                return NTSTATUS.STATUS_TIMEOUT;

            if (Remote != null && !IsEndpointAllowed(Instance, Remote))
            {
                try { Accepted.Dispose(); } catch { }
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;
            }

            int Sequence = _NextSequence++;
            _PendingAccepted[Sequence] = Accepted;

            Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
            BinaryPrimitives.WriteInt32LittleEndian(Data.OutputBuffer.AsSpan(0, 4), Sequence);

            if (Remote is IPEndPoint RemoteIp)
            {
                byte[] SockAddr = BuildSockaddr(RemoteIp);
                if (SockAddr.Length >= 16)
                    Buffer.BlockCopy(SockAddr, 0, Data.OutputBuffer, 4, 16);
            }

            Data.Information = 20;
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
            if (Data.InputBuffer.Length < MinSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            int Sequence = BitConverter.ToInt32(Data.InputBuffer, 4);
            ulong AcceptHandle = ReadPtr(Instance, Data.InputBuffer, 8);

            if (!_PendingAccepted.TryGetValue(Sequence, out Socket Accepted))
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

            int PtrSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4;
            int HeaderSize = PtrSize + 4 + 4 + 4;
            if (Data.InputBuffer.Length < HeaderSize)
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

            int PtrSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4;
            int HeaderSize = PtrSize + 4 + 4 + 4;
            if (Data.InputBuffer.Length < HeaderSize)
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

            if (Data.OutputBuffer == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            try
            {
                if (_socket.LocalEndPoint is not IPEndPoint LocalEndPoint)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                byte[] SockAddr = BuildSockaddr(LocalEndPoint);

                if (SockAddr.Length == 0)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                if (Data.OutputBuffer.Length < SockAddr.Length)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
                Buffer.BlockCopy(SockAddr, 0, Data.OutputBuffer, 0, SockAddr.Length);
                Data.Information = (ulong)SockAddr.Length;
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        private NTSTATUS IoctlPoll(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer == null || Data.OutputBuffer == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Data.OutputBuffer.Length < 16)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            uint Count = ReadU32(Data.InputBuffer, 8);
            if (Count == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int HeaderSize = 16;
            int EntrySize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 16 : 12;
            int Needed = HeaderSize + (int)Count * EntrySize;

            if (Data.InputBuffer.Length < Needed || Data.OutputBuffer.Length < Needed)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            int OutIndex = 0;
            Buffer.BlockCopy(Data.InputBuffer, 0, Data.OutputBuffer, 0, HeaderSize);

            for (int i = 0; i < Count; i++)
            {
                int EntryOffset = HeaderSize + i * EntrySize;

                ulong Handle = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? BitConverter.ToUInt64(Data.InputBuffer, EntryOffset)
                    : BitConverter.ToUInt32(Data.InputBuffer, EntryOffset);

                uint Requested = ReadU32(Data.InputBuffer, EntryOffset + (Instance._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4));

                WinFile? File = Instance.WinHelper.GetFileByHandle(Handle, AccessMask.GiveTemp);
                if (File?.Handler?.Target is not AfdDevice EndpointDevice || EndpointDevice._socket == null)
                    continue;

                Socket HostSocket = EndpointDevice._socket;

                bool ReadReady = false;
                bool WriteReady = false;
                bool ErrorReady = false;

                try
                {
                    ReadReady = HostSocket.Poll(0, SelectMode.SelectRead);
                    WriteReady = HostSocket.Poll(0, SelectMode.SelectWrite);
                    ErrorReady = HostSocket.Poll(0, SelectMode.SelectError);
                }
                catch
                {
                    ErrorReady = true;
                }

                uint Triggered = MapPollEventsToTriggered(Requested, ReadReady, WriteReady, ErrorReady, EndpointDevice.IsListening);
                if (Triggered == 0)
                    continue;

                int OutEntryOffset = HeaderSize + OutIndex * EntrySize;

                if (Instance._binary.Architecture == BinaryArchitecture.x64)
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset, 8), Handle);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 8, 4), Triggered);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 12, 4), (uint)NTSTATUS.STATUS_SUCCESS);
                }
                else
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset, 4), (uint)Handle);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 4, 4), Triggered);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(OutEntryOffset + 8, 4), (uint)NTSTATUS.STATUS_SUCCESS);
                }

                OutIndex++;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer.AsSpan(8, 4), (uint)OutIndex);

            if (OutIndex == 0)
                return NTSTATUS.STATUS_TIMEOUT;

            Data.Information = (ulong)(HeaderSize + OutIndex * EntrySize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        public NTSTATUS Handle(uint Ioctl, ref DeviceData Data, BinaryEmulator Instance)
        {
            NetworkAccessPolicy Policy = Instance.Settings.GetNetworkPolicy();
            if (!Policy.HasAnyAccess())
                return NTSTATUS.STATUS_NETWORK_UNREACHABLE;

            if (DecodeBase(Ioctl) != FsctlAfdBase)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

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
                    _ => NTSTATUS.STATUS_SUCCESS
                };
            }
            catch
            {
                return NTSTATUS.STATUS_UNSUCCESSFUL;
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
            Handler = static (uint Ioctl, ref DeviceData Data, BinaryEmulator Instance) => NTSTATUS.STATUS_SUCCESS;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}