using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    public static class AudioSrvPortHandler
    {
        public static readonly string[] PortNames =
        {
            AudioSrvPort,
            AudioClientRpcPort,
        };

        private const string AudioSrvPort = "\\RPC Control\\Audiosrv";
        private const string AudioClientRpcPort = "\\RPC Control\\AudioClientRpc";

        private const uint ProcGetPnpState = 0;
        private const uint ProcGetDefaultAudioEndpoint = 25;
        private const int PnpStateSize = 8;
        private const uint ProcGetMixFormat = 0;
        private const uint ProcGetDevicePeriod = 2;
        private const uint ProcInitialize = 4;
        private const uint ProcRelease = 5;
        private const uint ProcSetupStream = 7;
        private const uint ProcStartStream = 8;
        private const uint ProcStopStream = 9;

        private static readonly byte[] RenderEndpointClass =
            new Guid("cd773740-b187-4974-a1d5-e0ff91372277").ToByteArray();

        private sealed class AudioStream
        {
            public uint Id;
            public string EndpointId;
            public uint ShareMode;
            public uint StreamFlags;
            public ulong ControlBlock;
            public ulong SectionHandle;
            public ulong ServerSectionHandle;
            public uint RingBytes;
            public uint PeriodFrames;
            public string HandlePortName;
            public AudioStreamEngine Engine;
        }

        private static readonly Dictionary<uint, AudioStream> Streams = new Dictionary<uint, AudioStream>();
        private static uint NextStreamId = 1;

        private const uint ContextCookieMagic = 0x4F445541; // 'AUDO'

        private const ulong OffVersion = 0x000;
        private const ulong OffTotalSize = 0x004;
        private const ulong OffVolatileQueueRead = 0x008;
        private const ulong OffVolatileQueueWrite = 0x00C;
        private const ulong OffClientCursor = 0x018;
        private const ulong OffServerCursor = 0x020;
        private const ulong OffVolatileFlags = 0x0AC;
        private const ulong OffMagic = 0x0C8;
        private const ulong OffStaticSize = 0x0CC;
        private const ulong OffHandlePortName = 0x0D0;
        private const ulong OffQueueCount = 0x150;
        private const ulong OffBufferStart = 0x16C;
        private const ulong OffBufferEnd = 0x170;
        private const ulong OffBufferLimit = 0x174;
        private const ulong OffWaveFormat = 0x180;

        private const uint ControlDataVersion = 1;
        private const uint ControlDataMagic = 0x45504344; // 'DCPE'
        private const uint StaticControlDataSize = 220;

        private const uint RingBufferOffset = 0x200;
        private const uint DefaultBufferHns = 10_000_000;
        private const uint DefaultDevicePeriodHns = 100_000;
        private const uint MinimumDevicePeriodHns = 30_000;
        private const string HandlePortPrefix = "\\BaseNamedObjects\\AudioEngineDuplicateHandleApiPort";
        private const int HandlePortMessageSize = 48;
        private const int OffHandlePortStatus = 44;
        private const uint MaxRingBytes = 8 * 1024 * 1024;
        private const uint HundredNanosecondsPerSecond = 10_000_000;

        private const uint PageReadWrite = 0x04;
        private const uint ErrorNotEnoughMemory = 8;

        private const ushort WaveFormatExtensible = 0xFFFE;
        private const ushort MixChannels = 2;
        private const uint MixSampleRate = 48000;
        private const ushort MixBitsPerSample = 32;
        private const ushort MixBlockAlign = MixChannels * (MixBitsPerSample / 8);
        private const ushort WaveFormatExtensibleTail = 22;
        private const uint SpeakerFrontLeftRight = 3;

        /// <summary>
        /// The engine mix format, as a WAVEFORMATEXTENSIBLE.
        /// </summary>
        private static byte[] BuildMixFormat()
        {
            byte[] Format = new byte[18 + WaveFormatExtensibleTail];
            Span<byte> Cursor = Format;

            BinaryPrimitives.WriteUInt16LittleEndian(Cursor.Slice(0x00, 2), WaveFormatExtensible);
            BinaryPrimitives.WriteUInt16LittleEndian(Cursor.Slice(0x02, 2), MixChannels);
            BinaryPrimitives.WriteUInt32LittleEndian(Cursor.Slice(0x04, 4), MixSampleRate);
            BinaryPrimitives.WriteUInt32LittleEndian(Cursor.Slice(0x08, 4), MixSampleRate * MixBlockAlign);
            BinaryPrimitives.WriteUInt16LittleEndian(Cursor.Slice(0x0C, 2), MixBlockAlign);
            BinaryPrimitives.WriteUInt16LittleEndian(Cursor.Slice(0x0E, 2), MixBitsPerSample);
            BinaryPrimitives.WriteUInt16LittleEndian(Cursor.Slice(0x10, 2), WaveFormatExtensibleTail);
            BinaryPrimitives.WriteUInt16LittleEndian(Cursor.Slice(0x12, 2), MixBitsPerSample);
            BinaryPrimitives.WriteUInt32LittleEndian(Cursor.Slice(0x14, 4), SpeakerFrontLeftRight);
            KsDataFormatSubtypeIeeeFloat.CopyTo(Cursor.Slice(0x18, 16));

            return Format;
        }

        private static readonly byte[] KsDataFormatSubtypeIeeeFloat =
        {
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
        };

        private const uint RpcSProcnumOutOfRange = 1745;
        private const uint ErrorNotFound = 1168;

        private const uint DeviceStateActive = 1;
        private const string MMDevicesKey = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio";

        private const int MaxDumpBytes = 512;
        private const int DumpBytesPerLine = 32;

        public static NTSTATUS Handle(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (!LrpcPacket.TryParse(SendData, out LrpcMessage Message))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            switch (Message.Type)
            {
                case LrpcMessageType.Bind:
                    Reply.Data = LrpcPacket.BuildBindAccept(Message, out uint AcceptedSyntax);
                    Log(Instance, $"bind on \"{Port?.Name}\" accepted with syntax 0x{AcceptedSyntax:X}.");
                    break;

                case LrpcMessageType.Request:
                    Reply.Data = DispatchRequest(Port, Message, Reply, Instance);
                    break;

                default:
                    Log(Instance, $"unhandled message type {(ulong)Message.Type} on \"{Port?.Name}\" ({SendData.Length} bytes).");
                    Dump(Instance, "unhandled", SendData, LrpcPacket.HeaderSize);
                    break;
            }

            if (Reply.Data == null)
            {
                Reply.Data = new byte[LrpcPacket.HeaderSize];
                Array.Copy(SendData, Reply.Data, Math.Min(LrpcPacket.HeaderSize, SendData.Length));
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static byte[] DispatchRequest(WinPort Port, in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            bool IsStreamPort = string.Equals(Port?.Name, AudioClientRpcPort, StringComparison.OrdinalIgnoreCase);

            byte[] Response = IsStreamPort
                ? DispatchAudioClient(Message, Reply, Instance)
                : DispatchAudioSrv(Message, Instance);

            if (Response != null)
                return Response;

            Log(Instance, $"unimplemented proc {Message.ProcNumber} on \"{Port?.Name}\" ({Message.StubData.Length} stub bytes).");
            DumpStubData(Instance, Message);
            return LrpcPacket.BuildFault(Message, RpcSProcnumOutOfRange);
        }

        private static byte[] DispatchAudioSrv(in LrpcMessage Message, BinaryEmulator Instance)
        {
            switch (Message.ProcNumber)
            {
                case ProcGetPnpState:
                    return GetPnpState(Message, Instance);

                case ProcGetDefaultAudioEndpoint:
                    return GetDefaultAudioEndpoint(Message, Instance);

                default:
                    return null;
            }
        }

        private static byte[] GetPnpState(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Log(Instance, "PnP state polled.");

            Ndr20Writer Writer = new Ndr20Writer(32);
            Writer.WriteUInt32(PnpStateSize);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(PnpStateSize);
            Writer.WriteBytes(new byte[PnpStateSize]);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }


        private static byte[] DispatchAudioClient(in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            switch (Message.ProcNumber)
            {
                case ProcGetMixFormat:
                    return GetMixFormat(Message, Instance);

                case ProcGetDevicePeriod:
                    return GetDevicePeriod(Message, Instance);

                case ProcInitialize:
                    return InitializeStream(Message, Instance);

                case ProcRelease:
                    return ReleaseStream(Message, Instance);

                case ProcSetupStream:
                    return SetupStream(Message, Reply, Instance);

                case ProcStartStream:
                case ProcStopStream:
                    return AcknowledgeStreamTransition(Message, Instance);

                default:
                    return null;
            }
        }

        private static byte[] AcknowledgeStreamTransition(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            if (TryGetStream(Cookie, out AudioStream Stream))
                Log(Instance, $"stream {Stream.Id} {(Message.ProcNumber == ProcStartStream ? "started" : "stopped")}.");

            Ndr20Writer Writer = new Ndr20Writer(16);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] InitializeStream(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadConformantWideString(out string EndpointId);
            Reader.TryReadUInt16(out ushort ShareMode);
            Reader.Align(4);
            Reader.TryReadUInt32(out uint StreamFlags);

            AudioStream Stream = new AudioStream
            {
                Id = NextStreamId++,
                EndpointId = EndpointId,
                ShareMode = ShareMode,
                StreamFlags = StreamFlags,
            };

            Streams[Stream.Id] = Stream;
            Log(Instance, $"stream {Stream.Id} initialize: share mode {ShareMode}, flags 0x{StreamFlags:X}, endpoint {EndpointId}.");

            Ndr20Writer Writer = new Ndr20Writer(128);
            Writer.WriteUniqueWideString(Stream.EndpointId);
            Writer.WriteContextHandle(BuildContextCookie(Stream.Id));
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] SetupStream(in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);
            Reader.TryReadUInt16(out ushort ShareMode);
            Reader.TryReadUInt64(out ulong BufferHns);
            Reader.TryReadUInt64(out ulong PeriodHns);

            if (!TryGetStream(Cookie, out AudioStream Stream))
            {
                Log(Instance, "stream setup for an unknown context handle.");
                return LrpcPacket.BuildFault(Message, ErrorNotFound);
            }

            if (BufferHns == 0)
                BufferHns = DefaultBufferHns;

            Stream.RingBytes = RingBytesForDuration(BufferHns);
            Stream.PeriodFrames = FramesForDuration(PeriodHns != 0 ? PeriodHns : BufferHns);
            Stream.ShareMode = ShareMode;

            if (!TryCreateSharedBuffer(Instance, Stream))
                return LrpcPacket.BuildFault(Message, ErrorNotEnoughMemory);

            int SectionIndex = Reply.Handles?.Count ?? 0;
            Reply.AttachHandle(Stream.SectionHandle);

            Log(Instance, $"stream {Stream.Id} setup: {Stream.RingBytes} byte ring, {Stream.PeriodFrames} frames per period, section handle 0x{Stream.SectionHandle:X}.");

            Ndr20Writer Writer = new Ndr20Writer(256);
            WriteSystemAudioStream(ref Writer, Stream, SectionIndex);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] ReleaseStream(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            if (TryGetStream(Cookie, out AudioStream Stream))
            {
                Log(Instance, $"stream {Stream.Id} released after {Stream.Engine?.RenderedBytes ?? 0} bytes rendered.");

                bool EngineStopped = Stream.Engine?.Stop() ?? true;
                if (EngineStopped && Stream.ServerSectionHandle != 0)
                    Instance.WinHelper.CloseHandle(Stream.ServerSectionHandle);

                RemoveHandlePort(Instance, Stream);
                Streams.Remove(Stream.Id);
            }

            Ndr20Writer Writer = new Ndr20Writer(32);
            Writer.WriteContextHandle(ReadOnlySpan<byte>.Empty);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] GetMixFormat(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Log(Instance, $"mix format {MixChannels}ch {MixSampleRate}Hz float{MixBitsPerSample}.");

            Ndr20Writer Writer = new Ndr20Writer(96);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(WaveFormatExtensibleTail);
            Writer.WriteBytes(BuildMixFormat());
            Writer.AlignTo(4);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] GetDevicePeriod(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Log(Instance, $"device period {DefaultDevicePeriodHns / 10_000} ms default, {MinimumDevicePeriodHns / 10_000} ms minimum.");

            Ndr20Writer Writer = new Ndr20Writer(48);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt64(DefaultDevicePeriodHns);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt64(MinimumDevicePeriodHns);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] GetDefaultAudioEndpoint(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadUInt16(out ushort DataFlow);

            string Direction = DataFlow == 1 ? "Capture" : "Render";
            if (!TryFindActiveEndpoint(Instance, Direction, out string EndpointId))
            {
                Log(Instance, $"no active {Direction} endpoint in the registry.");
                return LrpcPacket.BuildFault(Message, ErrorNotFound);
            }

            Log(Instance, $"default {Direction} endpoint -> {EndpointId}.");

            Ndr20Writer Writer = new Ndr20Writer(96);
            Writer.WriteUniqueWideString(EndpointId);
            Writer.WriteUInt32(0);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static void WriteSystemAudioStream(ref Ndr20Writer Writer, AudioStream Stream, int SectionIndex)
        {
            Writer.AlignTo(8);
            Writer.WriteBytes(RenderEndpointClass);
            Writer.WriteUInt32(0);
            Writer.WriteSystemHandle(-1);
            Writer.WriteUInt64(0);
            Writer.WriteUInt64(0);
            WriteHandleBlob(ref Writer, -1);
            WriteHandleBlob(ref Writer, -1);
            WriteHandleBlob(ref Writer, -1);
            Writer.WriteUInt32(0);
            Writer.WriteUInt32(0);
            WriteHandleBlob(ref Writer, SectionIndex);
            Writer.WriteUInt32(1);
            Writer.WriteUInt32(Stream.PeriodFrames);
            Writer.WriteFloat(MixSampleRate);
            Writer.WriteUInt32(0);
        }

        private static void WriteHandleBlob(ref Ndr20Writer Writer, int HandleIndex)
        {
            uint Tag = HandleIndex < 0 ? 0u : 1u;

            Writer.AlignTo(4);
            Writer.WriteUInt16((ushort)Tag);
            Writer.AlignTo(4);
            Writer.WriteUInt32(Tag);

            if (HandleIndex >= 0)
                Writer.WriteSystemHandle(HandleIndex);
        }

        private static bool TryCreateSharedBuffer(BinaryEmulator Instance, AudioStream Stream)
        {
            ulong SectionSize = RingBufferOffset + Stream.RingBytes;

            ulong Backing = Instance.MapUniqueAddress(SectionSize, MemoryProtection.ReadWrite);
            if (Backing == 0)
                return false;

            Stream.ControlBlock = Backing;
            WriteStreamControlBlock(Instance, Stream);
            PublishHandlePort(Instance, Stream);

            Stream.SectionHandle = Instance.WinHelper.CreateSectionHandle(
                null, SectionSize, PageReadWrite, 0, null, Backing, AccessMask.StandardRightsAll).Handle;

            HoldServerSectionReference(Instance, Stream);

            // The engine walks the ring from a host thread, so it needs a host pointer into the section
            // rather than the emulator's memory accessors, which are only safe from the guest thread.
            IntPtr Host = Instance.GetHostPointer(Backing, SectionSize);
            if (Host == IntPtr.Zero)
            {
                Log(Instance, "no host pointer for the shared section; stream will not be audible.");
                return true;
            }

            Stream.Engine = new AudioStreamEngine(
                Host, RingBufferOffset, Stream.RingBytes,
                new AudioSinkFormat(MixSampleRate, MixChannels, MixBitsPerSample));

            Log(Instance, $"stream {Stream.Id} engine started on the {Stream.Engine.Backend} backend.");
            return true;
        }

        private static void HoldServerSectionReference(BinaryEmulator Instance, AudioStream Stream)
        {
            WinSection Section = Instance.WinHelper.GetSectionByHandle(Stream.SectionHandle, AccessMask.StandardRightsAll);
            if (Section == null)
                return;

            WinHandle ServerHandle = Instance.WinHelper.HandleManager.AddHandle(Section, AccessMask.StandardRightsAll);
            Instance.WinHelper.AddWinHandle(ServerHandle);
            Stream.ServerSectionHandle = ServerHandle.Handle;
        }

        private static void PublishHandlePort(BinaryEmulator Instance, AudioStream Stream)
        {
            Stream.HandlePortName = HandlePortPrefix + Stream.Id;

            Instance.WinHelper.WinPorts.Add(new WinPort
            {
                Name = Stream.HandlePortName,
                Handler = HandleEventPortMessage,
            });

            Instance.WriteMemory(Stream.ControlBlock + OffHandlePortName,
                Encoding.Unicode.GetBytes(Stream.HandlePortName + "\0"));
        }

        private static void RemoveHandlePort(BinaryEmulator Instance, AudioStream Stream)
        {
            if (Stream.HandlePortName == null)
                return;

            List<WinPort> Ports = Instance.WinHelper.WinPorts;
            for (int Index = Ports.Count - 1; Index >= 0; Index--)
            {
                if (string.Equals(Ports[Index].Name, Stream.HandlePortName, StringComparison.OrdinalIgnoreCase))
                    Ports.RemoveAt(Index);
            }
        }

        private static NTSTATUS HandleEventPortMessage(WinPort Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            ulong EventHandle = Port.ReceivedHandles is { Count: > 0 } ? Port.ReceivedHandles[0] : 0;

            if (EventHandle != 0 && TryGetStreamByHandlePort(Port.Name, out AudioStream Stream))
            {
                WinEvent Event = Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.EventAllAccess);
                Stream.Engine?.SetPeriodEvent(Event);
                Log(Instance, $"stream {Stream.Id} render event 0x{EventHandle:X} {(Event != null ? "attached" : "not resolvable")}.");
            }

            byte[] Response = new byte[Math.Max(SendData.Length, HandlePortMessageSize)];
            Array.Copy(SendData, Response, SendData.Length);
            BinaryPrimitives.WriteInt32LittleEndian(Response.AsSpan(OffHandlePortStatus, 4), 0);

            Reply.Data = Response;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryGetStreamByHandlePort(string PortName, out AudioStream Stream)
        {
            foreach (KeyValuePair<uint, AudioStream> Entry in Streams)
            {
                if (string.Equals(Entry.Value.HandlePortName, PortName, StringComparison.OrdinalIgnoreCase))
                {
                    Stream = Entry.Value;
                    return true;
                }
            }

            Stream = null;
            return false;
        }

        private static uint FramesForDuration(ulong DurationHns)
        {
            uint MaxFrames = MaxRingBytes / MixBlockAlign;
            ulong MaxDurationHns = (ulong)MaxFrames * HundredNanosecondsPerSecond / MixSampleRate;

            if (DurationHns >= MaxDurationHns)
                return MaxFrames;

            ulong Frames = DurationHns * MixSampleRate / HundredNanosecondsPerSecond;
            return Frames == 0 ? 1 : (uint)Frames;
        }

        private static uint RingBytesForDuration(ulong DurationHns)
        {
            return FramesForDuration(DurationHns) * MixBlockAlign;
        }

        private static void WriteStreamControlBlock(BinaryEmulator Instance, AudioStream Stream)
        {
            ulong Block = Stream.ControlBlock;
            uint BufferEnd = RingBufferOffset + Stream.RingBytes;

            Instance._emulator.WriteMemory(Block + OffVersion, ControlDataVersion);
            Instance._emulator.WriteMemory(Block + OffTotalSize, BufferEnd);
            Instance._emulator.WriteMemory(Block + OffMagic, ControlDataMagic);

            Instance._emulator.WriteMemory(Block + OffVolatileQueueRead, 0u);
            Instance._emulator.WriteMemory(Block + OffVolatileQueueWrite, 0u);
            Instance._emulator.WriteMemory(Block + OffClientCursor, 0UL, 8);
            Instance._emulator.WriteMemory(Block + OffServerCursor, 0UL, 8);
            Instance._emulator.WriteMemory(Block + OffVolatileFlags, 0u);

            Instance._emulator.WriteMemory(Block + OffStaticSize, StaticControlDataSize);
            Instance._emulator.WriteMemory(Block + OffQueueCount, 0u);
            Instance._emulator.WriteMemory(Block + OffBufferStart, RingBufferOffset);
            Instance._emulator.WriteMemory(Block + OffBufferEnd, BufferEnd);
            Instance._emulator.WriteMemory(Block + OffBufferLimit, BufferEnd);

            Instance.WriteMemory(Block + OffWaveFormat, BuildMixFormat());
        }

        private static byte[] BuildContextCookie(uint StreamId)
        {
            byte[] Cookie = new byte[Ndr20Writer.ContextHandleSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Cookie.AsSpan(0, 4), ContextCookieMagic);
            BinaryPrimitives.WriteUInt32LittleEndian(Cookie.AsSpan(4, 4), StreamId);
            return Cookie;
        }

        private static bool TryGetStream(ReadOnlySpan<byte> Cookie, out AudioStream Stream)
        {
            Stream = null;

            if (Cookie.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(Cookie) != ContextCookieMagic)
                return false;

            return Streams.TryGetValue(BinaryPrimitives.ReadUInt32LittleEndian(Cookie.Slice(4, 4)), out Stream);
        }

        private static bool TryFindActiveEndpoint(BinaryEmulator Instance, string Direction, out string EndpointId)
        {
            EndpointId = null;

            WinSysHelper Helper = Instance.WinHelper;
            string DirectionKey = MMDevicesKey + "\\" + Direction;

            WinHandle RootHandle = Helper.OpenRegistryKey(DirectionKey, AccessMask.GenericRead);
            if (RootHandle == null)
                return false;

            try
            {
                WinRegKey Root = Helper.HandleManager.GetObjectByHandle<WinRegKey>(RootHandle.Handle);
                if (Root == null || !Helper.TryCollectRegistrySubKeyNames(Root, out List<string> Names))
                    return false;

                foreach (string Name in Names)
                {
                    if (IsEndpointActive(Helper, DirectionKey + "\\" + Name))
                    {
                        EndpointId = Name;
                        return true;
                    }
                }
            }
            finally
            {
                Helper.CloseHandle(RootHandle.Handle);
            }

            return false;
        }

        private static bool IsEndpointActive(WinSysHelper Helper, string EndpointKey)
        {
            WinHandle Handle = Helper.OpenRegistryKey(EndpointKey, AccessMask.GenericRead);
            if (Handle == null)
                return false;

            try
            {
                WinRegKey Key = Helper.HandleManager.GetObjectByHandle<WinRegKey>(Handle.Handle);
                if (Key == null || !Helper.TryGetRegistryValue(Key, "DeviceState", out ValueNode State))
                    return false;

                return State.Data != null
                    && State.Data.Length >= 4
                    && BinaryPrimitives.ReadUInt32LittleEndian(State.Data) == DeviceStateActive;
            }
            finally
            {
                Helper.CloseHandle(Handle.Handle);
            }
        }

        public static void DumpConnectionMessage(BinaryEmulator Instance, string TargetPort, ulong ConnectionMessagePtr)
        {
            if (ConnectionMessagePtr == 0 || !IsAudioPort(TargetPort))
                return;

            if (!Instance.IsRegionMapped(ConnectionMessagePtr, LrpcPacket.HeaderSize))
                return;

            byte[] Header = Instance.ReadMemory(ConnectionMessagePtr, LrpcPacket.HeaderSize);
            if (Header == null)
                return;

            ushort TotalLength = (ushort)(Header[0x02] | (Header[0x03] << 8));
            if (TotalLength < LrpcPacket.HeaderSize || !Instance.IsRegionMapped(ConnectionMessagePtr, TotalLength))
                return;

            Dump(Instance, "connect", Instance.ReadMemory(ConnectionMessagePtr, TotalLength), LrpcPacket.HeaderSize);
        }

        private static bool IsAudioPort(string Name)
        {
            for (int Index = 0; Index < PortNames.Length; Index++)
            {
                if (string.Equals(PortNames[Index], Name, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static void DumpStubData(BinaryEmulator Instance, in LrpcMessage Message)
        {
            if (Message.Raw != null)
                Dump(Instance, "stub", Message.Raw, LrpcPacket.RequestStubDataOffset);
        }

        private static void Log(BinaryEmulator Instance, string Text)
        {
            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[AudioSrv] {Text}", LogFlags.General);
        }

        private static void Dump(BinaryEmulator Instance, string Label, byte[] Data, int Offset)
        {
            if ((Instance.Settings.Flags & LogFlags.General) == 0 || Data == null || Data.Length <= Offset)
                return;

            int Length = Data.Length - Offset;
            int Shown = Math.Min(Length, MaxDumpBytes);
            Instance.TriggerEventMessage($"[AudioSrv] {Label}: {Length} bytes.", LogFlags.General);

            for (int Pos = 0; Pos < Shown; Pos += DumpBytesPerLine)
            {
                int Count = Math.Min(DumpBytesPerLine, Shown - Pos);
                Instance.TriggerEventMessage($"[AudioSrv]   +{Pos:X4}  {Convert.ToHexString(Data, Offset + Pos, Count)}", LogFlags.General);
            }
        }
    }
}
