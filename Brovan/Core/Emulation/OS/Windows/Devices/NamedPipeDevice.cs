using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// One end of a guest named pipe. Messages carry a length prefix, because the channel underneath is a
    /// byte ring in both directions.
    /// </summary>
    internal sealed class GuestNamedPipe : IDisposable
    {
        internal const string DeviceName = "\\Device\\NamedPipe";

        internal const uint FSCTL_PIPE_DISCONNECT = 0x00110004;
        internal const uint FSCTL_PIPE_LISTEN = 0x00110008;
        internal const uint FSCTL_PIPE_PEEK = 0x0011400C;
        internal const uint FSCTL_PIPE_WAIT = 0x00110018;
        internal const uint FSCTL_PIPE_IMPERSONATE = 0x0011001C;
        internal const uint FSCTL_PIPE_TRANSCEIVE = 0x0011C017;

        internal const uint FILE_PIPE_BYTE_STREAM_MODE = 0;
        internal const uint FILE_PIPE_MESSAGE_MODE = 1;
        internal const uint FILE_PIPE_QUEUE_OPERATION = 0;
        internal const uint FILE_PIPE_COMPLETE_OPERATION = 1;

        private const uint PipeStateDisconnected = 1;
        private const uint PipeStateListening = 2;
        private const uint PipeStateConnected = 3;
        private const uint PipeStateClosing = 4;

        private const uint PipeEndClient = 0;
        private const uint PipeEndServer = 1;

        private const uint PipeConfigurationFullDuplex = 2;

        // FILE_PIPE_WAIT_FOR_BUFFER. Name follows the BOOLEAN on its own two byte alignment.
        private const int WaitNameLengthOffset = 8;
        private const int WaitTimeoutSpecifiedOffset = 12;
        private const int WaitNameOffset = 14;

        private const int FrameHeaderBytes = 4;
        private const int ReadChunkBytes = 0x1000;
        internal const int MaxMessageBytes = 0x400000;

        internal const int BlockingIoMilliseconds = 5000;
        internal const int PollSliceMilliseconds = 1;

        private readonly GuestPipeChannel Channel;
        private readonly byte[] ReadChunk;

        private byte[] Incoming = Array.Empty<byte>();
        private int IncomingStart;
        private int IncomingEnd;

        private byte[] Current;
        private int CurrentOffset;

        private byte[] PendingWriteFrame;
        private int PendingWriteLength;
        private int PendingWriteSent;
        private int PendingWriteBytes;
        private ulong PendingWriteOwner;

        private bool Disposed;

        private int IncomingCount => IncomingEnd - IncomingStart;

        internal string GuestPath { get; }

        internal bool IsRoot { get; }

        internal bool IsServer => Channel != null && Channel.IsServer;

        internal uint ReadMode { get; set; }

        internal uint CompletionMode { get; set; }

        internal uint PipeType => Channel == null ? FILE_PIPE_BYTE_STREAM_MODE : Channel.PipeType;

        internal uint MaximumInstances => Channel == null ? 1 : Channel.MaximumInstances;

        internal uint InboundQuota => Channel == null ? 0 : Channel.InboundQuota;

        internal uint OutboundQuota => Channel == null ? 0 : Channel.OutboundQuota;

        internal bool BlockingMode => CompletionMode != FILE_PIPE_COMPLETE_OPERATION;

        private GuestNamedPipe(string GuestPath)
        {
            this.GuestPath = GuestPath;
            IsRoot = true;
        }

        private GuestNamedPipe(string GuestPath, GuestPipeChannel Channel, uint ReadMode, uint CompletionMode)
        {
            this.GuestPath = GuestPath;
            this.Channel = Channel;
            this.ReadMode = ReadMode;
            this.CompletionMode = CompletionMode;
            ReadChunk = new byte[ReadChunkBytes];
        }

        internal static GuestNamedPipe CreateRoot(string GuestPath) => new GuestNamedPipe(GuestPath);

        internal static NTSTATUS TryCreateServer(string GuestPath, uint PipeType, uint ReadMode, uint CompletionMode,
            uint MaximumInstances, uint InboundQuota, uint OutboundQuota, out GuestNamedPipe Pipe)
        {
            Pipe = null;

            NTSTATUS Status = GuestPipeChannel.TryCreateServer(GuestPath, PipeType, MaximumInstances, InboundQuota, OutboundQuota, out GuestPipeChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Pipe = new GuestNamedPipe(GuestPath, Channel, ReadMode, CompletionMode);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS TryCreateClient(string GuestPath, out GuestNamedPipe Pipe)
        {
            Pipe = null;

            NTSTATUS Status = GuestPipeChannel.TryConnectClient(GuestPath, out GuestPipeChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Pipe = new GuestNamedPipe(GuestPath, Channel, Channel.PipeType, FILE_PIPE_QUEUE_OPERATION);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static bool IsPipePath(string DevicePath)
        {
            if (DevicePath == null || !DevicePath.StartsWith(DeviceName, StringComparison.OrdinalIgnoreCase))
                return false;

            return DevicePath.Length == DeviceName.Length || DevicePath[DeviceName.Length] == '\\';
        }

        private bool Connected => Channel != null && Channel.Connected;

        private bool PeerClosed => Channel == null || Channel.PeerClosed;

        internal uint State
        {
            get
            {
                if (IsRoot)
                    return PipeStateListening;

                if (Channel == null)
                    return PipeStateDisconnected;

                if (Connected)
                    return PeerClosed ? PipeStateClosing : PipeStateConnected;

                return IsServer ? PipeStateListening : PipeStateDisconnected;
            }
        }

        private void AppendIncoming(ReadOnlySpan<byte> Source)
        {
            if (IncomingEnd + Source.Length > Incoming.Length)
            {
                int Live = IncomingCount;

                if (IncomingStart != 0 && Live + Source.Length <= Incoming.Length)
                {
                    Incoming.AsSpan(IncomingStart, Live).CopyTo(Incoming);
                }
                else
                {
                    long Capacity = Math.Max(ReadChunkBytes, Incoming.Length == 0 ? ReadChunkBytes : (long)Incoming.Length * 2);
                    while (Capacity < Live + Source.Length)
                        Capacity *= 2;

                    byte[] Grown = new byte[Capacity];
                    Incoming.AsSpan(IncomingStart, Live).CopyTo(Grown);
                    Incoming = Grown;
                }

                IncomingStart = 0;
                IncomingEnd = Live;
            }

            Source.CopyTo(Incoming.AsSpan(IncomingEnd));
            IncomingEnd += Source.Length;
        }

        private void ResetIncoming()
        {
            IncomingStart = 0;
            IncomingEnd = 0;
        }

        private void Pump()
        {
            if (Disposed || IsRoot || Channel == null)
                return;

            while (true)
            {
                // One whole message has to fit even when the guest asked for less.
                if (IncomingCount >= FrameHeaderBytes + MaxMessageBytes)
                    return;

                int Got = Channel.Read(ReadChunk);
                if (Got <= 0)
                    return;

                AppendIncoming(ReadChunk.AsSpan(0, Got));
            }
        }

        private bool EnsureCurrent()
        {
            if (Current != null && CurrentOffset < Current.Length)
                return true;

            Current = null;
            CurrentOffset = 0;

            if (IncomingCount < FrameHeaderBytes)
                return false;

            int Length = BinaryPrimitives.ReadInt32LittleEndian(Incoming.AsSpan(IncomingStart, FrameHeaderBytes));
            if (Length < 0 || Length > MaxMessageBytes)
            {
                ResetIncoming();
                return false;
            }

            if (IncomingCount < FrameHeaderBytes + Length)
                return false;

            byte[] Message = new byte[Length];
            Incoming.AsSpan(IncomingStart + FrameHeaderBytes, Length).CopyTo(Message);

            IncomingStart += FrameHeaderBytes + Length;
            if (IncomingStart == IncomingEnd)
                ResetIncoming();

            Current = Message;
            return Length != 0;
        }

        private NTSTATUS EmptyStatus()
        {
            if (!Connected)
                return IsServer ? NTSTATUS.STATUS_PIPE_LISTENING : NTSTATUS.STATUS_PIPE_BROKEN;

            if (PeerClosed)
                return NTSTATUS.STATUS_PIPE_BROKEN;

            return NTSTATUS.STATUS_PIPE_EMPTY;
        }

        /// <summary>
        /// A message longer than the buffer answers STATUS_BUFFER_OVERFLOW, and the rest stays queued.
        /// </summary>
        internal NTSTATUS Read(Span<byte> Destination, out int Written)
        {
            Written = 0;

            if (IsRoot)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            Pump();
            if (!EnsureCurrent())
                return EmptyStatus();

            int Available = Current.Length - CurrentOffset;
            int Copy = Math.Min(Available, Destination.Length);
            Current.AsSpan(CurrentOffset, Copy).CopyTo(Destination);
            CurrentOffset += Copy;
            Written = Copy;

            bool Drained = CurrentOffset >= Current.Length;
            if (Drained)
                Current = null;

            if (ReadMode == FILE_PIPE_MESSAGE_MODE && !Drained)
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;

            return NTSTATUS.STATUS_SUCCESS;
        }

        /// <summary>
        /// STATUS_PENDING means the ring took only part of the message and the caller has to ask again.
        /// </summary>
        internal NTSTATUS Write(ReadOnlySpan<byte> Source, ulong Owner, out int Written)
        {
            Written = 0;

            if (IsRoot)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            Pump();

            if (Channel == null || !Connected)
                return IsServer ? NTSTATUS.STATUS_PIPE_LISTENING : NTSTATUS.STATUS_PIPE_BROKEN;

            if (Source.Length > MaxMessageBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (PendingWriteFrame == null)
            {
                int FrameLength = FrameHeaderBytes + Source.Length;
                PendingWriteFrame = ArrayPool<byte>.Shared.Rent(FrameLength);
                BinaryPrimitives.WriteInt32LittleEndian(PendingWriteFrame, Source.Length);
                Source.CopyTo(PendingWriteFrame.AsSpan(FrameHeaderBytes));

                PendingWriteLength = FrameLength;
                PendingWriteSent = 0;
                PendingWriteBytes = Source.Length;
                PendingWriteOwner = Owner;
            }
            else if (PendingWriteOwner != Owner)
            {
                return NTSTATUS.STATUS_PIPE_BUSY;
            }

            while (PendingWriteSent < PendingWriteLength)
            {
                int Moved = Channel.Write(PendingWriteFrame.AsSpan(PendingWriteSent, PendingWriteLength - PendingWriteSent));
                if (Moved <= 0)
                    break;

                PendingWriteSent += Moved;
            }

            if (PendingWriteSent < PendingWriteLength)
            {
                if (PeerClosed)
                {
                    ReleasePendingWrite();
                    return NTSTATUS.STATUS_PIPE_BROKEN;
                }

                return NTSTATUS.STATUS_PENDING;
            }

            Written = PendingWriteBytes;
            ReleasePendingWrite();
            return NTSTATUS.STATUS_SUCCESS;
        }

        private void ReleasePendingWrite()
        {
            if (PendingWriteFrame != null)
                ArrayPool<byte>.Shared.Return(PendingWriteFrame);

            PendingWriteFrame = null;
            PendingWriteLength = 0;
            PendingWriteSent = 0;
            PendingWriteBytes = 0;
            PendingWriteOwner = 0;
        }

        internal NTSTATUS HandleControl(uint ControlCode, ref DeviceData Data, BinaryEmulator Instance)
        {
            switch (ControlCode)
            {
                case FSCTL_PIPE_WAIT:
                    return Wait(ref Data);

                case FSCTL_PIPE_LISTEN:
                    return Listen();

                case FSCTL_PIPE_DISCONNECT:
                    return Disconnect();

                case FSCTL_PIPE_IMPERSONATE:
                    return NTSTATUS.STATUS_SUCCESS;

                case FSCTL_PIPE_PEEK:
                    return Peek(ref Data);

                case FSCTL_PIPE_TRANSCEIVE:
                    return Transceive(ref Data, Instance);

                default:
                    return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }
        }

        private NTSTATUS Listen()
        {
            if (Channel == null || !Channel.IsServer)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            if (Connected)
                return NTSTATUS.STATUS_PIPE_CONNECTED;

            if (CompletionMode == FILE_PIPE_COMPLETE_OPERATION)
                return NTSTATUS.STATUS_PIPE_LISTENING;

            return NTSTATUS.STATUS_PENDING;
        }

        /// <summary>
        /// STATUS_PENDING while no instance is listening.
        /// </summary>
        private NTSTATUS Wait(ref DeviceData Data)
        {
            if (!TryReadWaitName(Data.InputBuffer, Data.InputLength, out string Name))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return GuestPipeChannel.ServerExists(DeviceName + "\\" + Name)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_PENDING;
        }

        private static bool TryReadWaitName(byte[] InputBuffer, uint InputLength, out string Name)
        {
            Name = null;

            if (InputBuffer == null || InputLength < WaitNameOffset)
                return false;

            uint NameBytes = BinaryPrimitives.ReadUInt32LittleEndian(InputBuffer.AsSpan(WaitNameLengthOffset));
            if (NameBytes == 0 || NameBytes > InputLength - WaitNameOffset)
                return false;

            Name = Encoding.Unicode.GetString(InputBuffer, WaitNameOffset, (int)NameBytes).Trim('\\');
            return Name.Length != 0;
        }

        /// <summary>
        /// Clamped to the budget every other pipe operation uses.
        /// </summary>
        internal static int ReadWaitTimeoutMilliseconds(byte[] InputBuffer, uint InputLength)
        {
            if (InputBuffer == null || InputLength < WaitNameOffset || InputBuffer[WaitTimeoutSpecifiedOffset] == 0)
                return BlockingIoMilliseconds;

            long Timeout = BinaryPrimitives.ReadInt64LittleEndian(InputBuffer.AsSpan(0));
            if (Timeout >= 0)
                return BlockingIoMilliseconds;

            long Milliseconds = -Timeout / 10000;
            return Milliseconds <= 0 ? 0 : (int)Math.Min(Milliseconds, BlockingIoMilliseconds);
        }

        private NTSTATUS Disconnect()
        {
            if (Channel == null || !Channel.IsServer)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            ReleasePendingWrite();
            ResetIncoming();
            Current = null;
            CurrentOffset = 0;
            Channel.Disconnect();
            return NTSTATUS.STATUS_SUCCESS;
        }

        private int PumpAvailable()
        {
            Pump();
            EnsureCurrent();
            return Current == null ? 0 : Current.Length - CurrentOffset;
        }

        private NTSTATUS Peek(ref DeviceData Data)
        {
            const int HeaderBytes = 0x10;

            if (Data.OutputBuffer == null || Data.OutputLength < HeaderBytes)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            int Available = PumpAvailable();

            Span<byte> Output = Data.OutputBuffer.AsSpan(0, (int)Data.OutputLength);
            Output.Clear();

            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(0x00), State);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(0x04), (uint)Available);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(0x08), Available == 0 ? 0u : 1u);
            BinaryPrimitives.WriteUInt32LittleEndian(Output.Slice(0x0C), (uint)Available);

            int Copy = Math.Min(Available, Output.Length - HeaderBytes);
            if (Copy > 0)
                Current.AsSpan(CurrentOffset, Copy).CopyTo(Output.Slice(HeaderBytes));

            Data.Information = (ulong)(HeaderBytes + Copy);
            return Copy < Available ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS Transceive(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer != null && Data.InputLength != 0)
            {
                NTSTATUS WriteStatus = Write(Data.InputBuffer.AsSpan(0, (int)Data.InputLength), OwnerOf(Instance), out _);
                if (WriteStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Data.Information = 0;
                    return WriteStatus;
                }
            }

            if (Data.OutputBuffer == null || Data.OutputLength == 0)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS ReadStatus = Read(Data.OutputBuffer.AsSpan(0, (int)Data.OutputLength), out int Written);
            if (ReadStatus == NTSTATUS.STATUS_PIPE_EMPTY && BlockingMode)
                return NTSTATUS.STATUS_PENDING;

            Data.Information = (ulong)Written;
            return ReadStatus;
        }

        internal static ulong OwnerOf(BinaryEmulator Instance)
        {
            EmulatedThread Thread = Instance?.CurrentThread;
            return Thread == null ? 0ul : (ulong)Thread.ThreadId;
        }

        internal void WriteLocalInformation(Span<byte> Destination)
        {
            int Available = PumpAvailable();

            Destination.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x00), PipeType);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x04), PipeConfigurationFullDuplex);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x08), MaximumInstances);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x0C), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x10), InboundQuota);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x14), (uint)Available);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x18), OutboundQuota);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x1C), OutboundQuota);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x20), State);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x24), IsServer ? PipeEndServer : PipeEndClient);
        }

        public void Dispose()
        {
            if (Disposed)
                return;

            Disposed = true;

            ReleasePendingWrite();
            Channel?.Dispose();

            ResetIncoming();
            Current = null;
        }
    }

    internal sealed class NamedPipeDevice : IWinDevice
    {
        public string DeviceName => GuestNamedPipe.DeviceName;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            return CreatePipe(DevicePath, out InternalPath, out Handler, out _);
        }

        internal NTSTATUS CreatePipe(string DevicePath, out string InternalPath, out WinDeviceDelegate Handler, out GuestNamedPipe Pipe)
        {
            InternalPath = null;
            Handler = null;
            Pipe = null;

            bool Root = DevicePath.Length <= GuestNamedPipe.DeviceName.Length;

            if (Root)
            {
                Pipe = GuestNamedPipe.CreateRoot(DevicePath);
            }
            else
            {
                NTSTATUS Status = GuestNamedPipe.TryCreateClient(DevicePath, out Pipe);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            InternalPath = DevicePath;
            Handler = Pipe.HandleControl;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
