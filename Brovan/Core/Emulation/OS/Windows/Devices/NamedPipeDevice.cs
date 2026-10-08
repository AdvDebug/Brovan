using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace Brovan.Core.Emulation.OS.Windows
{
    // Keeps no data of its own, because an end inherited by another process must see every unread byte.
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
        private const uint PipeConfigurationInbound = 0;
        private const uint HostStreamQuotaBytes = 4096;

        // FILE_PIPE_WAIT_FOR_BUFFER. Name follows the BOOLEAN on its own two byte alignment.
        private const int WaitNameLengthOffset = 8;
        private const int WaitTimeoutSpecifiedOffset = 12;
        private const int WaitNameOffset = 14;

        private const int PeekHeaderBytes = 0x10;

        internal const int MaxMessageBytes = GuestPipeChannel.MaxFrameBytes;

        internal const int BlockingIoMilliseconds = 5000;
        internal const int PollSliceMilliseconds = 1;

        private static int AnonymousCounter;

        internal readonly GuestPipeChannel Channel;

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
        }

        internal static GuestNamedPipe CreateRoot(string GuestPath) => new GuestNamedPipe(GuestPath);

        // NT gives an anonymous pipe no name. The backing file still needs a unique one.
        internal static string NextAnonymousPath()
        {
            uint Counter = (uint)Interlocked.Increment(ref AnonymousCounter);
            return $"{DeviceName}\\Win32Pipes.{Environment.ProcessId:x8}.{Counter:x8}";
        }

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

            Pipe = new GuestNamedPipe(GuestPath, Channel, FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT opens the client end of one instance by an empty name relative to its server end.
        internal static NTSTATUS TryCreateClientOf(GuestNamedPipe Server, out GuestNamedPipe Pipe)
        {
            Pipe = null;

            if (Server?.Channel == null || !Server.IsServer)
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            NTSTATUS Status = GuestPipeChannel.TryConnectInstance(Server.Channel.BackingPath, Server.Channel.GuestName, out GuestPipeChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Pipe = new GuestNamedPipe(Server.GuestPath, Channel, FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS TryAttach(string GuestPath, string BackingPath, bool Server, uint Generation, uint ReadMode, uint CompletionMode, out GuestNamedPipe Pipe)
        {
            Pipe = null;

            NTSTATUS Status = GuestPipeChannel.TryOpenEnd(BackingPath, Server, Generation, out GuestPipeChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Pipe = new GuestNamedPipe(GuestPath, Channel, ReadMode, CompletionMode);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // False when the root is no pipe handle. Under the device root a name names a pipe, and an empty name
        // under a server end names that instance.
        internal static bool TryResolveRelative(BinaryEmulator Instance, ulong RootDirectory, string Name, out string GuestPath, out GuestNamedPipe Server)
        {
            GuestPath = null;
            Server = null;

            if (RootDirectory == 0)
                return false;

            GuestNamedPipe Root = Instance.WinHelper.HandleManager.GetObjectByHandle<WinFile>(RootDirectory)?.Pipe;
            if (Root == null)
                return false;

            if (Root.IsRoot)
            {
                if (!string.IsNullOrEmpty(Name))
                    GuestPath = DeviceName + "\\" + Name.TrimStart('\\');
                return true;
            }

            if (string.IsNullOrEmpty(Name) && Root.IsServer)
            {
                Server = Root;
                GuestPath = Root.GuestPath;
            }

            return true;
        }

        internal static bool IsPipePath(string DevicePath)
        {
            if (DevicePath == null || !DevicePath.StartsWith(DeviceName, StringComparison.OrdinalIgnoreCase))
                return false;

            return DevicePath.Length == DeviceName.Length || DevicePath[DeviceName.Length] == '\\';
        }

        internal uint State
        {
            get
            {
                if (IsRoot)
                    return PipeStateListening;

                if (Channel == null || Channel.Disconnected)
                    return PipeStateDisconnected;

                if (Channel.Connected)
                    return Channel.PeerClosed ? PipeStateClosing : PipeStateConnected;

                return IsServer ? PipeStateListening : PipeStateDisconnected;
            }
        }

        internal NTSTATUS UsableStatus(bool Writing)
        {
            if (IsRoot || Channel == null)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            if (Channel.Disconnected)
                return NTSTATUS.STATUS_PIPE_DISCONNECTED;

            if (Writing && Channel.OutboundBroken)
                return NTSTATUS.STATUS_PIPE_BROKEN;

            // NT lets a client read what the server wrote before it closed.
            if (IsServer && !Channel.Connected)
                return NTSTATUS.STATUS_PIPE_LISTENING;

            if (Writing && Channel.PeerClosed)
                return NTSTATUS.STATUS_PIPE_CLOSING;

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal NTSTATUS HandleControl(uint ControlCode, ref DeviceData Data, BinaryEmulator Instance)
        {
            switch (ControlCode)
            {
                case FSCTL_PIPE_WAIT:
                    return Wait(ref Data);

                case FSCTL_PIPE_DISCONNECT:
                    return Disconnect(Instance, Data.File);

                case FSCTL_PIPE_IMPERSONATE:
                    return NTSTATUS.STATUS_SUCCESS;

                case FSCTL_PIPE_PEEK:
                    return Peek(ref Data);

                default:
                    return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }
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
        /// Clamped to the budget the pipe wait uses.
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

        private NTSTATUS Disconnect(BinaryEmulator Instance, WinFile File)
        {
            if (Channel == null || !Channel.IsServer)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            Instance?.WinHelper?.PipeRequests.CompleteFile(Instance, File, NTSTATUS.STATUS_PIPE_DISCONNECTED);
            Channel.Disconnect();
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool HasPeekHeader(ref DeviceData Data)
        {
            if (Data.OutputBuffer != null && Data.OutputLength >= PeekHeaderBytes)
                return true;

            Data.Information = 0;
            return false;
        }

        // NT: NpPeek. A header-only buffer overflows while data is queued.
        private static NTSTATUS EndPeek(ref DeviceData Data, uint State, int Available, uint Messages, uint MessageLength, int Copied, bool MessageCut)
        {
            Span<byte> Header = Data.OutputBuffer.AsSpan(0, PeekHeaderBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x00), State);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x04), (uint)Available);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x08), Messages);
            BinaryPrimitives.WriteUInt32LittleEndian(Header.Slice(0x0C), MessageLength);
            Data.Information = (ulong)(PeekHeaderBytes + Copied);

            if (Data.OutputLength == PeekHeaderBytes)
                return Available != 0 ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;

            return MessageCut ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a peek waits behind a read of the same synchronous file.
        internal static NTSTATUS PeekHostStream(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (!HasPeekHeader(ref Data))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Task NextChange = GeneralHelper.HostStreamInput.NextChange;
            Span<byte> Output = Data.OutputBuffer.AsSpan(PeekHeaderBytes, (int)Data.OutputLength - PeekHeaderBytes);
            int Copied = GeneralHelper.HostStreamInput.Peek(Output, out int Available, out bool Ended);
            if (Ended)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_PIPE_BROKEN;
            }

            // A guest that polls with peeks must see data arrive.
            if (Available == 0)
            {
                GeneralHelper.HostStreamInput.Request(Instance.WakeSignal);
                return EndPeek(ref Data, PipeStateConnected, 0, 0, 0, 0, false);
            }

            if (!GeneralHelper.HostStreamInput.TryTakeWriterState(out bool Closed))
            {
                GeneralHelper.HostStreamInput.RequestWriterState(Instance.WakeSignal);
                WinPendingIo Io = Instance.WinHelper.SynchronousIo(Data.File, Data.EventHandle, Data.ApcRoutine, Data.ApcContext, Data.IoStatusBlock);
                return Instance.WinHelper.TryRetrySyscallWhenDone(NextChange, Io) ? NTSTATUS.STATUS_PENDING : NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            return EndPeek(ref Data, Closed ? PipeStateClosing : PipeStateConnected, Available, 0, 0, Copied, false);
        }

        private NTSTATUS Peek(ref DeviceData Data)
        {
            if (!HasPeekHeader(ref Data))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Usable = UsableStatus(false);
            int Available = Channel == null ? 0 : Channel.InboundPayload;
            if (Usable != NTSTATUS.STATUS_SUCCESS)
            {
                Data.Information = 0;
                return Usable == NTSTATUS.STATUS_PIPE_LISTENING ? NTSTATUS.STATUS_INVALID_PIPE_STATE : Usable;
            }

            if (Available == 0 && Channel.PeerClosed)
            {
                Data.Information = 0;
                return NTSTATUS.STATUS_PIPE_BROKEN;
            }

            Span<byte> Output = Data.OutputBuffer.AsSpan(0, (int)Data.OutputLength);
            Output.Clear();

            bool MessagePipe = PipeType == FILE_PIPE_MESSAGE_MODE;
            int Copied = Channel.Peek(Output.Slice(PeekHeaderBytes), MessagePipe, out uint MessageLength);
            if (!MessagePipe)
                return EndPeek(ref Data, State, Available, 0, 0, Copied, false);

            return EndPeek(ref Data, State, Available, Available == 0 ? 0u : 1u, MessageLength, Copied, Copied < MessageLength);
        }

        internal void WriteLocalInformation(Span<byte> Destination)
        {
            int Available = Channel == null ? 0 : Channel.InboundPayload;
            int WriteSpace = Channel == null ? 0 : Channel.OutboundFree;

            Destination.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x00), PipeType);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x04), PipeConfigurationFullDuplex);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x08), MaximumInstances);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x0C), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x10), InboundQuota);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x14), (uint)Available);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x18), OutboundQuota);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x1C), (uint)WriteSpace);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x20), State);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x24), IsServer ? PipeEndServer : PipeEndClient);
        }

        // An inbound byte pipe, as CreatePipe makes it.
        internal static void WriteHostStreamLocalInformation(Span<byte> Destination, HostStreamKind Kind)
        {
            int Available = 0;
            bool Ended = false;
            if (Kind == HostStreamKind.Input)
                GeneralHelper.HostStreamInput.Peek(Span<byte>.Empty, out Available, out Ended);

            Destination.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x00), FILE_PIPE_BYTE_STREAM_MODE);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x04), PipeConfigurationInbound);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x08), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x0C), 1);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x10), HostStreamQuotaBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x14), (uint)Available);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x18), HostStreamQuotaBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x1C), HostStreamQuotaBytes);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x20), Ended ? PipeStateClosing : PipeStateConnected);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x24), Kind == HostStreamKind.Input ? PipeEndServer : PipeEndClient);
        }

        public void Dispose()
        {
            Channel?.Dispose();
        }
    }

    internal enum PipeRequestKind : byte
    {
        Read,
        Write,
        Listen,
        Transceive
    }

    internal sealed class PipeRequest : ParkedIoRequest
    {
        internal PipeRequestKind Kind;
        internal WinPendingIo Io;
        internal GuestNamedPipe Pipe;
        internal uint Token;
        internal ulong Buffer;
        internal int Length;
        internal byte[] Data;
        internal bool DataPooled;
        internal int DataLength;
        internal int Offset;
        internal bool WriteDone;
        internal bool PieceStarted;
        internal bool HoldsReadLock;
        internal bool HoldsWriteLock;
        internal ulong Information;

        internal override WinFile File => Io.File;

        internal override string WaitLabel => $"pipe-io {Kind}";

        internal bool UsesInbound => Kind == PipeRequestKind.Read || (Kind == PipeRequestKind.Transceive && WriteDone);

        internal bool UsesOutbound => Kind == PipeRequestKind.Write || (Kind == PipeRequestKind.Transceive && !WriteDone);
    }

    // The scheduler polls these, because data from another process does not wake this one.
    internal sealed class PipeRequestQueue
    {
        private readonly List<PipeRequest> Pending = new List<PipeRequest>();
        private uint NextToken;

        internal int Count => Pending.Count;

        private uint TakeToken()
        {
            NextToken++;
            if (NextToken == 0)
                NextToken = 1;
            return NextToken;
        }

        internal PipeRequest Create(BinaryEmulator Instance, PipeRequestKind Kind, WinFile File, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlock)
        {
            WinEvent Event = EventHandle == 0 ? null : Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.GiveTemp);

            return new PipeRequest
            {
                Kind = Kind,
                Io = new WinPendingIo(File, Instance.CurrentThreadId, Event, ApcRoutine, ApcContext, IoStatusBlock),
                Pipe = File.Pipe,
                Token = TakeToken(),
            };
        }

        // NT waits inside the call on a synchronous file, so the calling thread parks until the request ends.
        internal NTSTATUS Submit(BinaryEmulator Instance, PipeRequest Request)
        {
            bool Queued = IsBlockedByEarlier(Request, Pending.Count);
            if (!Queued && TryProgress(Instance, Request))
            {
                Finish(Instance, Request, false);
                return Request.Status;
            }

            if (!Request.Pipe.BlockingMode && Request.Kind != PipeRequestKind.Write)
            {
                // Part of a message larger than the ring is already in the buffer.
                Request.Status = Request.Kind == PipeRequestKind.Listen ? NTSTATUS.STATUS_PIPE_LISTENING :
                    Request.Offset != 0 ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_PIPE_EMPTY;
                Request.Information = (ulong)Request.Offset;
                ReleaseLocks(Request);
                Request.Completed = true;
                Finish(Instance, Request, false);
                return Request.Status;
            }

            if (!Request.Pipe.BlockingMode)
            {
                Request.Status = NTSTATUS.STATUS_SUCCESS;
                Request.Information = (ulong)Request.Offset;
                ReleaseLocks(Request);
                Request.Completed = true;
                Finish(Instance, Request, false);
                return Request.Status;
            }

            Pending.Add(Request);

            if (Request.File.Synchronous)
                Instance.WinHelper.ParkForIoRequest(Request);

            return NTSTATUS.STATUS_PENDING;
        }

        internal void Poll(BinaryEmulator Instance)
        {
            if (Pending.Count == 0)
                return;

            for (int i = 0; i < Pending.Count; i++)
            {
                PipeRequest Request = Pending[i];

                if (!Instance.WinHelper.IsPendingIoLive(in Request.Io))
                {
                    Pending.RemoveAt(i--);
                    End(Request, NTSTATUS.STATUS_CANCELLED, 0);
                    Finish(Instance, Request, true);
                    continue;
                }

                if (IsBlockedByEarlier(Request, i))
                    continue;

                if (!TryProgress(Instance, Request))
                    continue;

                Pending.RemoveAt(i--);
                Finish(Instance, Request, true);
            }
        }

        // NT queues the requests on one end and direction in order.
        private bool IsBlockedByEarlier(PipeRequest Request, int Index)
        {
            for (int i = 0; i < Index; i++)
            {
                PipeRequest Earlier = Pending[i];
                if (!ReferenceEquals(Earlier.Pipe, Request.Pipe))
                    continue;

                if ((Earlier.UsesInbound && Request.UsesInbound) || (Earlier.UsesOutbound && Request.UsesOutbound))
                    return true;
            }

            return false;
        }

        // A zero IoStatusBlock matches every request on the file, and a negative thread id matches every thread.
        internal int Cancel(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, int ThreadId)
        {
            int Cancelled = 0;
            for (int i = 0; i < Pending.Count; i++)
            {
                PipeRequest Request = Pending[i];
                if (!ReferenceEquals(Request.File, File))
                    continue;

                if (IoStatusBlock != 0 && Request.Io.IoStatusBlock != IoStatusBlock)
                    continue;

                if (ThreadId >= 0 && Request.Io.ThreadId != ThreadId)
                    continue;

                Pending.RemoveAt(i--);
                End(Request, NTSTATUS.STATUS_CANCELLED, 0);
                Finish(Instance, Request, true);
                Cancelled++;
            }

            return Cancelled;
        }

        internal void CancelThread(BinaryEmulator Instance, int ThreadId)
        {
            for (int i = 0; i < Pending.Count; i++)
            {
                PipeRequest Request = Pending[i];
                if (Request.Io.ThreadId != ThreadId || WinSysHelper.CompletesToPort(in Request.Io))
                    continue;

                Pending.RemoveAt(i--);
                End(Request, NTSTATUS.STATUS_CANCELLED, 0);
                Finish(Instance, Request, true);
            }
        }

        internal void CompleteFile(BinaryEmulator Instance, WinFile File, NTSTATUS Status)
        {
            for (int i = 0; i < Pending.Count; i++)
            {
                PipeRequest Request = Pending[i];
                if (!ReferenceEquals(Request.File, File))
                    continue;

                Pending.RemoveAt(i--);
                End(Request, Status, 0);
                Finish(Instance, Request, true);
            }
        }

        private static void End(PipeRequest Request, NTSTATUS Status, ulong Information)
        {
            Request.Status = Status;
            Request.Information = Information;
            Request.Completed = true;
            ReleaseLocks(Request);
        }

        private static void ReleaseLocks(PipeRequest Request)
        {
            GuestPipeChannel Channel = Request.Pipe?.Channel;
            if (Channel == null)
                return;

            if (Request.HoldsReadLock)
            {
                Channel.UnlockRead(Request.Token);
                Request.HoldsReadLock = false;
            }

            if (Request.HoldsWriteLock)
            {
                Channel.UnlockWrite(Request.Token);
                Request.HoldsWriteLock = false;
            }
        }

        private static void ReleaseData(PipeRequest Request)
        {
            if (Request.Data != null && Request.DataPooled)
                ArrayPool<byte>.Shared.Return(Request.Data);

            Request.Data = null;
            Request.DataPooled = false;
        }

        // A message is copied whole when it is issued, even when it enters the ring in pieces.
        internal static bool TryTakeData(BinaryEmulator Instance, PipeRequest Request, ulong Source, int Length)
        {
            Request.DataLength = Length;
            if (Length == 0)
                return true;

            Request.DataPooled = (uint)Length <= Brovan.Core.Settings.MemoryBudget.PooledIoBytes;
            Request.Data = Request.DataPooled ? ArrayPool<byte>.Shared.Rent(Length) : new byte[Length];

            if (Instance.ReadMemory(Source, Request.Data.AsSpan(0, Length)))
                return true;

            ReleaseData(Request);
            return false;
        }

        // NT gives a request that failed without pending no APC and no completion packet. Only a transceive still
        // writes the IO_STATUS_BLOCK and the event.
        private static void Finish(BinaryEmulator Instance, PipeRequest Request, bool Pended)
        {
            ReleaseData(Request);

            bool Failed = ((uint)Request.Status >> 30) == 3;
            if (!Pended && Failed && Request.Kind != PipeRequestKind.Transceive)
                return;

            Instance.WinHelper.CompletePendingIo(in Request.Io, Request.Status, Request.Information, Pended || !Failed, Pended);

            if (Pended)
                Instance.WakeSignal.Bump();
        }

        private static bool TryProgress(BinaryEmulator Instance, PipeRequest Request)
        {
            switch (Request.Kind)
            {
                case PipeRequestKind.Read:
                    return ProgressRead(Instance, Request);

                case PipeRequestKind.Write:
                    return ProgressWrite(Instance, Request);

                case PipeRequestKind.Listen:
                    return ProgressListen(Request);

                case PipeRequestKind.Transceive:
                    if (!Request.WriteDone)
                    {
                        if (!ProgressWrite(Instance, Request))
                            return false;

                        if (Request.Status != NTSTATUS.STATUS_SUCCESS)
                            return true;

                        Request.WriteDone = true;
                        Request.Offset = 0;
                        Request.Completed = false;
                    }

                    return ProgressRead(Instance, Request);

                default:
                    End(Request, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                    return true;
            }
        }

        private static bool ProgressListen(PipeRequest Request)
        {
            GuestPipeChannel Channel = Request.Pipe.Channel;
            if (Channel == null || !Channel.IsServer)
            {
                End(Request, NTSTATUS.STATUS_ILLEGAL_FUNCTION, 0);
                return true;
            }

            if (!Channel.Connected)
                return false;

            End(Request, NTSTATUS.STATUS_SUCCESS, 0);
            return true;
        }

        private static bool ProgressRead(BinaryEmulator Instance, PipeRequest Request)
        {
            GuestNamedPipe Pipe = Request.Pipe;
            GuestPipeChannel Channel = Pipe.Channel;

            NTSTATUS Usable = Pipe.UsableStatus(false);
            if (Usable != NTSTATUS.STATUS_SUCCESS)
            {
                End(Request, Usable, (ulong)Request.Offset);
                return true;
            }

            if (!Request.HoldsReadLock)
            {
                if (!Channel.TryLockRead(Request.Token))
                    return false;

                Request.HoldsReadLock = true;
            }

            bool Done = Request.Length == 0
                ? ReadNothing(Request)
                : Pipe.ReadMode == GuestNamedPipe.FILE_PIPE_MESSAGE_MODE ? ReadMessage(Instance, Request) : ReadBytes(Instance, Request);

            if (!Done && Request.Offset == 0)
                ReleaseLocks(Request);

            if (!Done && Channel.PeerClosed && !Channel.InboundHasBytes)
            {
                End(Request, NTSTATUS.STATUS_PIPE_BROKEN, (ulong)Request.Offset);
                return true;
            }

            return Done;
        }

        // A zero-byte read waits for data to arrive and leaves it queued.
        private static bool ReadNothing(PipeRequest Request)
        {
            if (!Request.Pipe.Channel.InboundHasBytes)
                return false;

            End(Request, NTSTATUS.STATUS_SUCCESS, 0);
            return true;
        }

        private static bool ReadBytes(BinaryEmulator Instance, PipeRequest Request)
        {
            GuestPipeChannel Channel = Request.Pipe.Channel;
            int Wanted = Math.Min(Request.Length, (int)Channel.InboundQuota);
            Span<byte> Scratch = Instance.WinHelper.Shared.GetSpan((uint)Wanted).Slice(0, Wanted);

            int Copied = Channel.ReadBytes(Scratch);
            if (Copied == 0)
                return false;

            NTSTATUS Status = Instance._emulator.WriteMemory(Request.Buffer, Scratch.Slice(0, Copied))
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_ACCESS_VIOLATION;

            End(Request, Status, (ulong)Copied);
            return true;
        }

        private static bool ReadMessage(BinaryEmulator Instance, PipeRequest Request)
        {
            GuestPipeChannel Channel = Request.Pipe.Channel;
            int Wanted = Math.Min(Request.Length - Request.Offset, (int)Channel.InboundQuota);
            Span<byte> Scratch = Instance.WinHelper.Shared.GetSpan((uint)Math.Max(Wanted, 1)).Slice(0, Wanted);

            if (!Channel.ReadMessage(Scratch, out int Copied, out bool MessageLeft))
                return false;

            if (Copied != 0 && !Instance._emulator.WriteMemory(Request.Buffer + (ulong)Request.Offset, Scratch.Slice(0, Copied)))
            {
                End(Request, NTSTATUS.STATUS_ACCESS_VIOLATION, (ulong)Request.Offset);
                return true;
            }

            Request.Offset += Copied;

            if (Request.Offset == Request.Length || !MessageLeft)
            {
                End(Request, MessageLeft ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS, (ulong)Request.Offset);
                return true;
            }

            // A message larger than the ring. The read lock stays until all of it is read.
            return false;
        }

        // Read as the ring frees up, so a large write needs no host copy.
        private static bool TryWriteGuestBytes(BinaryEmulator Instance, PipeRequest Request)
        {
            GuestPipeChannel Channel = Request.Pipe.Channel;
            int Chunk = Math.Min(Request.DataLength - Request.Offset, Channel.OutboundFree);
            if (Chunk <= 0)
                return true;

            Span<byte> Scratch = Instance.WinHelper.Shared.GetSpan((uint)Chunk).Slice(0, Chunk);
            if (!Instance.ReadMemory(Request.Buffer + (ulong)Request.Offset, Scratch))
                return false;

            Request.Offset += Channel.WriteBytes(Scratch);
            return true;
        }

        private static bool ProgressWrite(BinaryEmulator Instance, PipeRequest Request)
        {
            GuestNamedPipe Pipe = Request.Pipe;
            GuestPipeChannel Channel = Pipe.Channel;

            NTSTATUS Usable = Pipe.UsableStatus(true);
            if (Usable != NTSTATUS.STATUS_SUCCESS)
            {
                End(Request, Usable, (ulong)Request.Offset);
                return true;
            }

            bool MessagePipe = Pipe.PipeType == GuestNamedPipe.FILE_PIPE_MESSAGE_MODE;
            if (Request.DataLength == 0 && !MessagePipe)
            {
                End(Request, NTSTATUS.STATUS_SUCCESS, 0);
                return true;
            }

            if (!Request.HoldsWriteLock)
            {
                if (!Channel.TryLockWrite(Request.Token))
                    return false;

                Request.HoldsWriteLock = true;
            }

            ReadOnlySpan<byte> Rest = Request.Data == null
                ? ReadOnlySpan<byte>.Empty
                : Request.Data.AsSpan(Request.Offset, Request.DataLength - Request.Offset);

            if (!MessagePipe && Request.Data == null)
            {
                if (!TryWriteGuestBytes(Instance, Request))
                {
                    End(Request, NTSTATUS.STATUS_ACCESS_VIOLATION, (ulong)Request.Offset);
                    return true;
                }
            }
            else if (!MessagePipe)
            {
                Request.Offset += Channel.WriteBytes(Rest);
            }
            else if (Channel.FitsOutbound(Request.DataLength))
            {
                if (!Channel.TryWriteFrame(Rest))
                {
                    ReleaseLocks(Request);
                    return false;
                }

                Request.Offset = Request.DataLength;
            }
            else if (Pipe.BlockingMode)
            {
                // A non-blocking writer never starts a message it cannot finish.
                int Taken = Channel.WriteMessagePiece(Rest, Request.DataLength, !Request.PieceStarted);
                if (Taken >= 0)
                {
                    Request.PieceStarted = true;
                    Request.Offset += Taken;
                }
            }

            if (Request.Offset == Request.DataLength)
            {
                End(Request, NTSTATUS.STATUS_SUCCESS, (ulong)Request.DataLength);
                return true;
            }

            // A message part way into the ring keeps the write lock, or another writer would split it.
            if (!Request.PieceStarted)
                ReleaseLocks(Request);

            return false;
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
