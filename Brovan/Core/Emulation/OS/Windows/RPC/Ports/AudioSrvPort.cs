using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
        private const uint ProcGetTsAudioProtocol = 5;
        private const uint ProcRegisterTsAudioProtocolNotification = 6;
        private const uint ProcUnregisterTsAudioProtocolNotification = 7;
        private const uint ProcGetDefaultAudioEndpoint = 25;
        private const int PnpInfoSize = 12;
        private const uint ProcGetMixFormat = 0;
        private const uint ProcIsFormatSupported = 1;
        private const uint ProcGetDevicePeriod = 2;
        private const uint ProcInitialize = 4;
        private const uint ProcRelease = 5;
        private const uint ProcSetupStream = 7;
        private const uint ProcStartStream = 8;
        private const uint ProcStopStream = 9;
        private const uint ProcGetStreamLatency = 14;
        private const uint ProcGetAudioSession = 6;
        private const uint ProcGetStreamChannelCount = 16;
        private const uint ProcSetStreamChannelVolume = 17;
        private const uint ProcGetStreamChannelVolume = 18;
        private const uint ProcSetAllStreamVolumes = 19;
        private const uint ProcGetAllStreamVolumes = 21;
        private const uint ProcSetAllInitialStreamVolumes = 22;
        private const uint ProcSessionGetId = 23;
        private const uint ProcSessionGetInstanceId = 24;
        private const uint ProcSessionGetProcessId = 26;
        private const uint ProcSessionGetState = 27;
        private const uint ProcSessionIsSystemSounds = 30;
        private const uint ProcSessionGetDisplayName = 32;
        private const uint ProcSessionSetDisplayName = 33;
        private const uint ProcSessionGetIconPath = 34;
        private const uint ProcSessionSetIconPath = 35;
        private const uint ProcSessionGetGroupingParam = 36;
        private const uint ProcSessionSetGroupingParam = 37;
        private const uint ProcSessionGetVolume = 38;
        private const uint ProcSessionSetVolume = 39;
        private const uint ProcSessionGetMute = 40;
        private const uint ProcSessionSetMute = 41;
        private const uint ProcSessionGetChannelCount = 42;
        private const uint ProcSessionSetChannelVolume = 43;
        private const uint ProcSessionGetChannelVolume = 44;
        private const uint ProcSessionSetAllVolumes = 45;
        private const uint ProcSessionGetAllVolumes = 46;
        private const uint ProcSessionSetDuckingPreference = 52;
        private const uint ProcSessionDestroy = 55;
        private const uint ProcDeriveStreamCategory = 122;

        private static readonly Guid RenderEndpointClass = new Guid("cd773740-b187-4974-a1d5-e0ff91372277");
        private static readonly Guid CaptureEndpointClass = new Guid("f64a6da6-e8af-4b7b-bca8-847ae765d538");

        private sealed class AudioStream
        {
            public uint Id;
            public string EndpointId;
            public bool Capture;
            public uint ShareMode;
            public uint StreamFlags;
            public WaveFormat Format;
            public ulong ControlBlock;
            public ulong SectionHandle;
            public ulong ServerSectionHandle;
            public uint RingBytes;
            public uint PeriodFrames;
            public string HandlePortName;
            public AudioEngine Engine;
            public uint QueueOffset;
            public uint QueueCount;
            public AudioSession Session;
            public float[] ChannelVolumes;
            public bool Running;
        }

        private sealed class AudioSession
        {
            public string EndpointId;
            public Guid SessionGuid;
            public string Id;
            public Guid GroupingParam;
            public string DisplayName = string.Empty;
            public string IconPath = string.Empty;
            public float Volume = 1f;
            public uint MuteValue;
            public readonly float[] ChannelVolumes = { 1f, 1f };
            public readonly List<AudioStream> Streams = new List<AudioStream>();
            public int Handles;
        }

        private static readonly Dictionary<(string, Guid), AudioSession> Sessions = new Dictionary<(string, Guid), AudioSession>();
        private static readonly Dictionary<uint, AudioSession> SessionHandles = new Dictionary<uint, AudioSession>();
        private static uint NextSessionHandle = 1;

        private static readonly Dictionary<uint, AudioStream> Streams = new Dictionary<uint, AudioStream>();
        private static uint NextStreamId = 1;

        private const uint ContextCookieMagic = 0x4F445541; // 'AUDO'
        private const uint TsNotificationCookieMagic = 0x4E505354; // 'TSPN'
        private const uint SessionCookieMagic = 0x53455341; // 'ASES'

        private const int OffVersion = 0x000;
        private const int OffTotalSize = 0x004;
        private const int OffMagic = 0x0C8;
        private const int OffStaticSize = 0x0CC;
        private const int OffHandlePortName = 0x0D0;
        private const int OffQueueCount = 0x150;
        private const int OffBufferStart = 0x16C;
        private const int OffBufferEnd = 0x170;
        private const int OffBufferLimit = 0x174;
        private const int OffWaveFormat = 0x180;
        private const int OffSecondaryQueueOffset = 0x0BC;
        private const int OffQueueOffset = 0x168;
        private const uint NoSecondaryQueue = uint.MaxValue;
        private const uint MaxCapturePackets = 1023;

        private const uint ControlDataVersion = 1;
        private const uint ControlDataMagic = 0x45504344; // 'DCPE'
        private const uint StaticControlDataSize = 220;

        private const uint RingBufferOffset = 0x200;
        private const uint DefaultBufferHns = 10_000_000;
        private const uint MinimumBufferHns = 1_500_000;
        private const uint DefaultDevicePeriodHns = 100_000;
        private const uint MinimumDevicePeriodHns = 30_000;
        private const string HandlePortPrefix = "\\BaseNamedObjects\\AudioEngineDuplicateHandleApiPort";
        private const int HandlePortMessageSize = 48;
        private const int OffHandlePortStatus = 44;
        private const uint MaxRingBytes = 8 * 1024 * 1024;
        private const uint HundredNanosecondsPerSecond = 10_000_000;

        private const uint PageReadWrite = 0x04;
        private const uint ErrorNotEnoughMemory = 8;

        private const ushort AudioShareModeExclusive = 1;
        private const uint StreamFlagAutoConvertPcm = 0x80000000;
        private const ushort MixChannels = 2;
        private const uint MixSampleRate = 48000;
        private const ushort MixBitsPerSample = 32;

        private static readonly WaveFormat MixFormat = WaveFormat.Extensible(MixChannels, MixSampleRate, MixBitsPerSample, MixBitsPerSample,
            AudioSampleConverter.SpeakerFrontLeft | AudioSampleConverter.SpeakerFrontRight, WaveFormat.SubtypeIeeeFloat);

        // The engine converts rates from AUDIO_MIN_FRAMERATE to AUDIO_MAX_FRAMERATE.
        private const uint MinConvertibleSampleRate = 10;
        private const uint MaxConvertibleSampleRate = 384000;
        private const ushort MaxStreamChannels = 4095;

        // These offsets are for the NDR wire form of the vadserver.cpp VadServerSettings structure.
        private const int VadServerSettingsWireSize = 176;
        private const int VadSettingsBlobCountOffset = 112;
        private const int VadSettingsBlobPointerOffset = 116;

        private const uint StreamCategoryMax = 14;
        private const uint RawStreamCategoryMax = 23;

        // This is the audiosrv DeriveAudioServerStreamCategory table, indexed by AUDIO_STREAM_CATEGORY.
        private static readonly uint[] DerivedStreamCategories =
        {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x15, 0x16, 0x17,
        };

        private const uint RpcSProcnumOutOfRange = LrpcPacket.RpcSProcnumOutOfRange;
        private const uint RpcXBadStubData = LrpcPacket.RpcXBadStubData;
        private const uint ErrorNotFound = 1168;
        private const int EAccessDenied = unchecked((int)0x80070005);
        private const int EInvalidArg = unchecked((int)0x80070057);
        private const int SFalse = 1;
        private const int AudioClientNotInitialized = unchecked((int)0x88890001);
        private const int AudioClientUnsupportedFormat = unchecked((int)0x88890008);
        private const uint RpcXInvalidBound = 1734;
        private const uint MaxVolumeQueryChannels = 32;
        private const ushort AudioSessionStateInactive = 0;
        private const ushort AudioSessionStateActive = 1;

        private const uint CallerSession = uint.MaxValue;
        private const uint TsAudioProtocolLocal = 0;
        private const uint TsAudioProtocolUnknown = 0xFFFF;

        private const uint DeviceStateActive = 1;
        private const string MMDevicesKey = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio";
        private const string CaptureEndpointPrefix = "{0.0.1.";
        private const string MicrophoneConsentKey = "\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone";
        private const string ConsentDenied = "Deny";

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

            Reply.Data ??= LrpcPacket.EchoHeader(SendData);

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

                case ProcGetTsAudioProtocol:
                    return GetTsAudioProtocol(Message, Instance);

                case ProcRegisterTsAudioProtocolNotification:
                    return RegisterTsAudioProtocolNotification(Message);

                case ProcUnregisterTsAudioProtocolNotification:
                    return UnregisterTsAudioProtocolNotification(Message);

                case ProcGetDefaultAudioEndpoint:
                    return GetDefaultAudioEndpoint(Message, Instance);

                default:
                    return null;
            }
        }

        // _MMPNPINFO is { cbSize, generation, interface count } (audiosrv s_winmmGetPnpInfo). The generation
        // counts the endpoints that arrived, so winmm enumerates on the first poll.
        private static byte[] GetPnpState(in LrpcMessage Message, BinaryEmulator Instance)
        {
            int Generation = ScanActiveEndpoints(Instance, "Render", false, out _) + ScanActiveEndpoints(Instance, "Capture", false, out _);
            Log(Instance, $"PnP state polled, generation {Generation}.");

            Ndr20Writer Writer = new Ndr20Writer(32);
            Writer.WriteUInt32(PnpInfoSize);
            Writer.WriteUniqueReferent();
            Writer.WriteUInt32(PnpInfoSize);
            Writer.WriteUInt32(PnpInfoSize);
            Writer.WriteInt32(Generation);
            Writer.WriteUInt32(0);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        // AudioSrvPolicyManager!TS_SessionGetAudioProtocol
        private static byte[] GetTsAudioProtocol(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            if (!Reader.TryReadUInt32(out uint SessionId))
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            uint CallerSessionId = GetCallerSessionId(Instance);
            if (SessionId == CallerSession)
                SessionId = CallerSessionId;

            uint Protocol = TsAudioProtocolUnknown;
            int Result = 0;

            if (CallerSessionId != 0 && SessionId != CallerSessionId)
                Result = EAccessDenied;
            else if (SessionId == 0 || SessionId == WinToken.InteractiveSessionId)
                Protocol = TsAudioProtocolLocal;

            Log(Instance, $"session {SessionId} audio protocol 0x{Protocol:X}, hr 0x{Result:X8}.");

            Ndr20Writer Writer = new Ndr20Writer(16);
            Writer.WriteUInt32(Protocol);
            Writer.WriteUInt32(0);
            Writer.WriteInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        // The protocol of a session never changes here, so a registration never fires.
        private static byte[] RegisterTsAudioProtocolNotification(in LrpcMessage Message)
        {
            Ndr20Writer Writer = new Ndr20Writer(32);
            WriteCookie(ref Writer, TsNotificationCookieMagic, 0);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] UnregisterTsAudioProtocolNotification(in LrpcMessage Message)
        {
            return LrpcPacket.BuildResponse(Message, Ndr20Writer.BuildContextHandleReply(Guid.Empty));
        }

        private static uint GetCallerSessionId(BinaryEmulator Instance)
        {
            return NtQueryInformationToken.EffectiveToken(Instance)?.SessionId ?? WinToken.InteractiveSessionId;
        }

        private static byte[] DispatchAudioClient(in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            switch (Message.ProcNumber)
            {
                case ProcGetMixFormat:
                    return GetMixFormat(Message, Instance);

                case ProcIsFormatSupported:
                    return IsFormatSupported(Message, Instance);

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

                case ProcGetStreamLatency:
                    return GetStreamLatency(Message);

                case ProcGetAudioSession:
                    return GetAudioSession(Message, Instance);

                case ProcGetStreamChannelCount:
                case ProcSetStreamChannelVolume:
                case ProcGetStreamChannelVolume:
                case ProcSetAllStreamVolumes:
                case ProcGetAllStreamVolumes:
                case ProcSetAllInitialStreamVolumes:
                    return DispatchStreamVolume(Message);

                case >= ProcSessionGetId and <= ProcSessionDestroy:
                    return DispatchSession(Message, Instance);

                case ProcDeriveStreamCategory:
                    return DeriveStreamCategory(Message);

                default:
                    return null;
            }
        }

        private static byte[] AcknowledgeStreamTransition(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            if (TryGetStream(Cookie, out AudioStream Stream))
            {
                Stream.Running = Message.ProcNumber == ProcStartStream;
                Log(Instance, $"stream {Stream.Id} {(Stream.Running ? "started" : "stopped")}.");
            }

            Ndr20Writer Writer = new Ndr20Writer(16);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        // audiosrv runs these checks in this order, and the first rule broken decides the status
        // (CVADServer::RuntimeClassInitialize).
        private static byte[] InitializeStream(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            if (!Reader.TryReadConformantWideString(out string EndpointId)
                || !Reader.TryReadUInt16(out ushort ShareMode)
                || !Reader.TryReadUInt32(out uint StreamFlags)
                || !WaveFormat.TryRead(ref Reader, out WaveFormat Format)
                || !Reader.TryReadGuid(out Guid SessionGuid)
                || !TrySkipVadServerSettings(ref Reader))
            {
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);
            }

            bool Capture = EndpointId != null && EndpointId.StartsWith(CaptureEndpointPrefix, StringComparison.Ordinal);

            int Result = 0;
            if (ShareMode > AudioShareModeExclusive || !Format.IsValid())
                Result = EInvalidArg;
            else if (Capture && !IsMicrophoneAllowed(Instance))
                Result = EAccessDenied;

            if (Result < 0)
            {
                Log(Instance, $"stream initialize refused with 0x{Result:X8}: {Format}.");
                return BuildInitializeReply(Message, null, Result);
            }

            AudioStream Stream = new AudioStream
            {
                Id = NextStreamId++,
                EndpointId = EndpointId,
                Capture = Capture,
                ShareMode = ShareMode,
                StreamFlags = StreamFlags,
                Format = Format,
            };

            AttachSession(Stream, SessionGuid);

            Streams[Stream.Id] = Stream;
            Log(Instance, $"stream {Stream.Id} initialize: share mode {ShareMode}, flags 0x{StreamFlags:X}, {Format}, endpoint {EndpointId}.");

            return BuildInitializeReply(Message, Stream, 0);
        }

        private static byte[] BuildInitializeReply(in LrpcMessage Message, AudioStream Stream, int Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(128);
            Writer.WriteUniqueWideString(Stream?.EndpointId);

            if (Stream == null)
                Writer.WriteContextHandle(ReadOnlySpan<byte>.Empty);
            else
                WriteCookie(ref Writer, ContextCookieMagic, Stream.Id);

            Writer.WriteInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] SetupStream(in LrpcMessage Message, PortReply Reply, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);
            Reader.TryReadUInt16(out _);
            Reader.TryReadUInt64(out ulong BufferHns);
            Reader.TryReadUInt64(out ulong PeriodHns);

            if (!TryGetStream(Cookie, out AudioStream Stream))
            {
                Log(Instance, "stream setup for an unknown context handle.");
                return LrpcPacket.BuildFault(Message, ErrorNotFound);
            }

            int Accepted = AcceptStreamFormat(Stream);
            if (Accepted < 0)
            {
                Log(Instance, $"stream {Stream.Id} setup refused with 0x{Accepted:X8}: {Stream.Format}.");
                return BuildSetupReply(Message, null, -1, Accepted);
            }

            if (BufferHns == 0)
                BufferHns = DefaultBufferHns;

            if (BufferHns < MinimumBufferHns)
                BufferHns = MinimumBufferHns;

            uint MaxFrames = MaxRingBytes / Stream.Format.BlockAlign;
            Stream.RingBytes = FramesForDuration(BufferHns, Stream.Format.SampleRate, MaxFrames) * Stream.Format.BlockAlign;
            Stream.PeriodFrames = FramesForDuration(PeriodHns != 0 ? PeriodHns : DefaultDevicePeriodHns, Stream.Format.SampleRate, MaxFrames);

            // A capture packet must sit whole in the ring, because the client copies it out in one piece.
            if (Stream.Capture)
            {
                uint PacketBytes = Stream.PeriodFrames * Stream.Format.BlockAlign;
                uint Packets = Math.Clamp(Stream.RingBytes / PacketBytes, 1u, MaxCapturePackets);
                Stream.RingBytes = Packets * PacketBytes;
                Stream.QueueCount = Packets + 1;
                Stream.QueueOffset = (uint)BinaryEmulator.AlignUp(RingBufferOffset + Stream.RingBytes, AudioCaptureEngine.QueueItemSize);
            }

            Stream.ChannelVolumes = new float[Stream.Format.Channels];
            Array.Fill(Stream.ChannelVolumes, 1f);

            if (!TryCreateSharedBuffer(Instance, Stream))
                return LrpcPacket.BuildFault(Message, ErrorNotEnoughMemory);

            PublishGains(Stream);

            int SectionIndex = Reply.Handles?.Count ?? 0;
            Reply.AttachHandle(Stream.SectionHandle);

            Log(Instance, $"stream {Stream.Id} setup: {Stream.RingBytes} byte ring, {Stream.PeriodFrames} frames per period, section handle 0x{Stream.SectionHandle:X}.");

            return BuildSetupReply(Message, Stream, SectionIndex, 0);
        }

        private static byte[] BuildSetupReply(in LrpcMessage Message, AudioStream Stream, int SectionIndex, int Result)
        {
            Ndr20Writer Writer = new Ndr20Writer(256);
            WriteSystemAudioStream(ref Writer, Stream, SectionIndex);
            Writer.WriteInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static int AcceptStreamFormat(AudioStream Stream)
        {
            WaveFormat Format = Stream.Format;

            if (Format.BlockAlign != Format.Channels * Format.BitsPerSample / 8 || Format.Channels > MaxStreamChannels)
                return EInvalidArg;

            if (Format.SampleType == AudioSampleType.None)
                return AudioClientUnsupportedFormat;

            if (Stream.ShareMode == AudioShareModeExclusive)
                return CheckExclusiveFormat(Format);

            int Support = CheckSharedFormat(Format);
            if (Support == 0)
                return 0;

            bool Convertible = Support == SFalse
                && (Stream.StreamFlags & StreamFlagAutoConvertPcm) != 0
                && Format.SampleRate >= MinConvertibleSampleRate
                && Format.SampleRate <= MaxConvertibleSampleRate;

            return Convertible ? 0 : AudioClientUnsupportedFormat;
        }

        private static byte[] ReleaseStream(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            if (TryGetStream(Cookie, out AudioStream Stream))
            {
                Log(Instance, $"stream {Stream.Id} released after {Stream.Engine?.TransferredBytes ?? 0} bytes.");

                bool EngineStopped = Stream.Engine?.Stop() ?? true;
                if (EngineStopped && Stream.ServerSectionHandle != 0)
                    Instance.WinHelper.CloseHandle(Stream.ServerSectionHandle);

                RemoveHandlePort(Instance, Stream);
                Streams.Remove(Stream.Id);
                DetachSession(Stream);
            }

            return LrpcPacket.BuildResponse(Message, Ndr20Writer.BuildContextHandleReply(Guid.Empty));
        }

        private static byte[] GetMixFormat(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Log(Instance, $"mix format {MixFormat}.");

            Ndr20Writer Writer = new Ndr20Writer(96);
            MixFormat.WriteUnique(ref Writer);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        // audiosrv runs these checks in this order, and the first rule broken decides the status
        // (AudioServerIsFormatSupported).
        private static byte[] IsFormatSupported(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            if (!Reader.TryReadConformantWideString(out string EndpointId)
                || !Reader.TryReadUInt16(out ushort ShareMode)
                || !TrySkipVadServerSettings(ref Reader)
                || !WaveFormat.TryRead(ref Reader, out WaveFormat Format)
                || !Reader.TryReadUInt32(out uint ClosestReferent))
            {
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);
            }

            int Result;
            bool OfferClosest = false;

            if (ShareMode != AudioShareModeExclusive && ClosestReferent == 0)
                Result = EInvalidArg;
            else if (Format.Tag == WaveFormat.TagExtensible && Format.ExtraSize < WaveFormat.ExtensibleTailSize)
                Result = EInvalidArg;
            else if (ShareMode == AudioShareModeExclusive)
                Result = CheckExclusiveFormat(Format);
            else
            {
                Result = CheckSharedFormat(Format);
                OfferClosest = Result == SFalse;
            }

            Log(Instance, $"format query on endpoint {EndpointId}, share mode {ShareMode}: {Format} -> 0x{Result:X8}.");

            Ndr20Writer Writer = new Ndr20Writer(96);
            if (ClosestReferent != 0)
                Writer.WriteUniqueReferent();

            if (OfferClosest)
                MixFormat.WriteUnique(ref Writer);
            else
                Writer.WriteUInt32(0);

            Writer.WriteInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        // The checks follow vadserver.cpp IsStreamFormatSupportedForMixFormat for an endpoint without processing objects.
        private static int CheckSharedFormat(in WaveFormat Format)
        {
            if ((Format.BitsPerSample & 0xFFF8) > 0x100)
                return AudioClientUnsupportedFormat;

            bool WholeValidBytes = Format.Tag != WaveFormat.TagExtensible || (Format.ValidBitsPerSample & 7) == 0;

            WaveFormat Converted = Format.ConvertPcmToFloat();
            if (!Converted.IsValidUncompressed())
                return AudioClientUnsupportedFormat;

            bool MatchesMix = Converted.SampleRate == MixFormat.SampleRate
                && Converted.Channels == MixFormat.Channels
                && Converted.BitsPerSample == MixFormat.BitsPerSample
                && WholeValidBytes
                && Format.IsValid();

            return MatchesMix ? 0 : SFalse;
        }

        // Exclusive mode has no closest match to offer, the caller either takes the engine format or fails.
        private static int CheckExclusiveFormat(in WaveFormat Format)
        {
            bool Matches = Format.IsValid()
                && Format.IsFloat
                && Format.Channels == MixFormat.Channels
                && Format.SampleRate == MixFormat.SampleRate
                && Format.BitsPerSample == MixFormat.BitsPerSample;

            return Matches ? 0 : AudioClientUnsupportedFormat;
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

        // Native reports zero latency for a device without a hardware latency property.
        private static byte[] GetStreamLatency(in LrpcMessage Message)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            Ndr20Writer Writer = new Ndr20Writer(16);
            Writer.WriteUInt64(0);
            Writer.WriteInt32(TryGetStream(Cookie, out _) ? 0 : AudioClientNotInitialized);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] GetAudioSession(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            Ndr20Writer Writer = new Ndr20Writer(32);
            if (!TryGetStream(Cookie, out AudioStream Stream))
            {
                Writer.WriteContextHandle(ReadOnlySpan<byte>.Empty);
                Writer.WriteInt32(AudioClientNotInitialized);
                return LrpcPacket.BuildResponse(Message, Writer.ToArray());
            }

            uint Handle = NextSessionHandle++;
            SessionHandles[Handle] = Stream.Session;
            Stream.Session.Handles++;
            Log(Instance, $"stream {Stream.Id} session handle {Handle} opened.");

            WriteCookie(ref Writer, SessionCookieMagic, Handle);
            Writer.WriteInt32(0);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static byte[] DispatchStreamVolume(in LrpcMessage Message)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);
            TryGetStream(Cookie, out AudioStream Stream);

            float[] Volumes = Stream?.ChannelVolumes;
            uint Channels = (uint)(Volumes?.Length ?? 0);
            int NotReady = Volumes == null ? AudioClientNotInitialized : 0;
            Ndr20Writer Writer = new Ndr20Writer(64);
            int Result;

            switch (Message.ProcNumber)
            {
                case ProcGetStreamChannelCount:
                    Writer.WriteUInt32(Channels);
                    Writer.WriteInt32(NotReady);
                    return LrpcPacket.BuildResponse(Message, Writer.ToArray());

                case ProcSetStreamChannelVolume:
                {
                    if (!Reader.TryReadUInt32(out uint Index) || !Reader.TryReadFloat(out float Level) || !Reader.TryReadUniqueUInt32(out bool WantUnchanged, out _))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    bool Unchanged = false;
                    Result = !IsValidLevel(Level) ? EInvalidArg : NotReady != 0 ? NotReady : StoreLevel(Volumes, Index, Level, out Unchanged);
                    if (Result == 0 && !Unchanged)
                        PublishGains(Stream);

                    Writer.WriteUniqueUInt32(WantUnchanged, Unchanged ? 1u : 0u);
                    Writer.WriteInt32(Result);
                    return LrpcPacket.BuildResponse(Message, Writer.ToArray());
                }

                case ProcGetStreamChannelVolume:
                {
                    if (!Reader.TryReadUInt32(out uint Index))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    Result = NotReady != 0 ? NotReady : Index >= Channels ? EInvalidArg : 0;
                    Writer.WriteFloat(Result == 0 ? Volumes[Index] : 0f);
                    Writer.WriteInt32(Result);
                    return LrpcPacket.BuildResponse(Message, Writer.ToArray());
                }

                case ProcSetAllStreamVolumes:
                case ProcSetAllInitialStreamVolumes:
                {
                    bool WantUnchanged = false;
                    if (!Reader.TryReadUInt32(out uint Count) || !TryReadLevels(ref Reader, Count, out ReadOnlySpan<float> Levels))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    if (Message.ProcNumber == ProcSetAllStreamVolumes ? !Reader.TryReadUniqueUInt32(out WantUnchanged, out _) : !Reader.TryReadUInt64(out _))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    bool Changed = false;
                    Result = NotReady != 0 ? NotReady : StoreLevels(Volumes, Levels, out Changed);
                    if (Changed)
                        PublishGains(Stream);

                    if (Message.ProcNumber == ProcSetAllStreamVolumes)
                        Writer.WriteUniqueUInt32(WantUnchanged, Changed ? 0u : 1u);

                    Writer.WriteInt32(Result);
                    return LrpcPacket.BuildResponse(Message, Writer.ToArray());
                }

                case ProcGetAllStreamVolumes:
                {
                    if (!Reader.TryReadUInt32(out uint Count))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    if (Count > MaxVolumeQueryChannels)
                        return LrpcPacket.BuildFault(Message, RpcXInvalidBound);

                    Result = NotReady != 0 ? NotReady : Count != Channels ? EInvalidArg : 0;
                    WriteLevels(ref Writer, Count, Result == 0 ? Volumes : null);
                    Writer.WriteInt32(Result);
                    return LrpcPacket.BuildResponse(Message, Writer.ToArray());
                }

                default:
                    return null;
            }
        }

        private static byte[] DispatchSession(in LrpcMessage Message, BinaryEmulator Instance)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            Reader.TryReadContextHandle(out ReadOnlySpan<byte> Cookie);

            if (!TryGetSession(Cookie, out uint Handle, out AudioSession Session))
            {
                Log(Instance, $"session proc {Message.ProcNumber} on an unknown session handle.");
                return LrpcPacket.BuildFault(Message, ErrorNotFound);
            }

            Ndr20Writer Writer = new Ndr20Writer(128);
            int Result = 0;

            switch (Message.ProcNumber)
            {
                case ProcSessionSetDuckingPreference:
                {
                    if (!Reader.TrySkip(1))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    Writer.WriteInt32(0);
                    return LrpcPacket.BuildResponse(Message, Writer.ToArray());
                }

                case ProcSessionDestroy:
                    SessionHandles.Remove(Handle);
                    Session.Handles--;
                    ReleaseSessionIfUnused(Session);
                    return LrpcPacket.BuildResponse(Message, Ndr20Writer.BuildContextHandleReply(Guid.Empty));
            }

            Writer.WriteContextHandle(Cookie);

            switch (Message.ProcNumber)
            {
                case ProcSessionGetId:
                    Writer.WriteUniqueWideString(GetSessionId(Session, Instance));
                    break;

                case ProcSessionGetInstanceId:
                    Writer.WriteUniqueWideString($"{GetSessionId(Session, Instance)}|1%b{Instance.WinHelper.PID}");
                    break;

                case ProcSessionGetProcessId:
                    Writer.WriteUInt32(Instance.WinHelper.PID);
                    break;

                case ProcSessionGetState:
                    Writer.WriteUInt16(Session.Streams.Exists(Stream => Stream.Running) ? AudioSessionStateActive : AudioSessionStateInactive);
                    Writer.AlignTo(4);
                    break;

                case ProcSessionIsSystemSounds:
                    Result = SFalse;
                    break;

                case ProcSessionGetDisplayName:
                    Writer.WriteUniqueWideString(Session.DisplayName);
                    break;

                case ProcSessionGetIconPath:
                    Writer.WriteUniqueWideString(Session.IconPath);
                    break;

                case ProcSessionSetDisplayName:
                case ProcSessionSetIconPath:
                {
                    if (!Reader.TryReadConformantWideString(out string Text) || !Reader.TryReadUniqueGuid(out _))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    if (Message.ProcNumber == ProcSessionSetDisplayName)
                        Session.DisplayName = Text;
                    else
                        Session.IconPath = Text;
                    break;
                }

                case ProcSessionGetGroupingParam:
                    Writer.WriteGuid(Session.GroupingParam);
                    break;

                case ProcSessionSetGroupingParam:
                {
                    if (!Reader.TryReadGuid(out Guid Grouping) || !Reader.TryReadUniqueGuid(out _))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    Session.GroupingParam = Grouping;
                    break;
                }

                case ProcSessionGetVolume:
                    Writer.WriteFloat(Session.Volume);
                    break;

                case ProcSessionSetVolume:
                {
                    if (!Reader.TryReadFloat(out float Level) || !Reader.TryReadUniqueGuid(out _) || !Reader.TryReadUniqueUInt32(out bool WantUnchanged, out _))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    bool Unchanged = false;
                    if (!IsValidLevel(Level))
                        Result = EInvalidArg;
                    else
                    {
                        Unchanged = Session.Volume == Level;
                        Session.Volume = Level;
                        if (!Unchanged)
                            PublishSessionGains(Session);
                    }

                    Writer.WriteUniqueUInt32(WantUnchanged, Unchanged ? 1u : 0u);
                    break;
                }

                case ProcSessionGetMute:
                    Writer.WriteUInt32(Session.MuteValue);
                    break;

                case ProcSessionSetMute:
                {
                    if (!Reader.TryReadUInt32(out uint Mute) || !Reader.TryReadUniqueGuid(out _) || !Reader.TryReadUniqueUInt32(out bool WantUnchanged, out _))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    bool Unchanged = Session.MuteValue == Mute;
                    Session.MuteValue = Mute;
                    if (!Unchanged)
                        PublishSessionGains(Session);

                    Writer.WriteUniqueUInt32(WantUnchanged, Unchanged ? 1u : 0u);
                    break;
                }

                case ProcSessionGetChannelCount:
                    Writer.WriteUInt32((uint)Session.ChannelVolumes.Length);
                    break;

                case ProcSessionGetChannelVolume:
                {
                    if (!Reader.TryReadUInt32(out uint Index))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    bool InRange = Index < Session.ChannelVolumes.Length;
                    Writer.WriteFloat(InRange ? Session.ChannelVolumes[Index] : 0f);
                    Result = InRange ? 0 : EInvalidArg;
                    break;
                }

                case ProcSessionSetChannelVolume:
                {
                    if (!Reader.TryReadUInt32(out uint Index) || !Reader.TryReadFloat(out float Level)
                        || !Reader.TryReadUniqueGuid(out _) || !Reader.TryReadUniqueUInt32(out bool WantUnchanged, out _))
                    {
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);
                    }

                    Result = StoreLevel(Session.ChannelVolumes, Index, Level, out bool Unchanged);
                    if (Result == 0 && !Unchanged)
                        PublishSessionGains(Session);

                    Writer.WriteUniqueUInt32(WantUnchanged, Unchanged ? 1u : 0u);
                    break;
                }

                case ProcSessionSetAllVolumes:
                {
                    if (!Reader.TryReadUInt32(out uint Count) || !TryReadLevels(ref Reader, Count, out ReadOnlySpan<float> Levels)
                        || !Reader.TryReadUniqueGuid(out _) || !Reader.TryReadUniqueUInt32(out bool WantUnchanged, out _))
                    {
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);
                    }

                    Result = StoreLevels(Session.ChannelVolumes, Levels, out bool Changed);
                    if (Changed)
                        PublishSessionGains(Session);

                    Writer.WriteUniqueUInt32(WantUnchanged, Changed ? 0u : 1u);
                    break;
                }

                case ProcSessionGetAllVolumes:
                {
                    if (!Reader.TryReadUInt32(out uint Count))
                        return LrpcPacket.BuildFault(Message, RpcXBadStubData);

                    if (Count > MaxVolumeQueryChannels)
                        return LrpcPacket.BuildFault(Message, RpcXInvalidBound);

                    Result = Count == Session.ChannelVolumes.Length ? 0 : EInvalidArg;
                    WriteLevels(ref Writer, Count, Result == 0 ? Session.ChannelVolumes : null);
                    break;
                }

                default:
                    Log(Instance, $"unimplemented session proc {Message.ProcNumber}.");
                    DumpStubData(Instance, Message);
                    return LrpcPacket.BuildFault(Message, RpcSProcnumOutOfRange);
            }

            Writer.AlignTo(4);
            Writer.WriteInt32(Result);
            return LrpcPacket.BuildResponse(Message, Writer.ToArray());
        }

        private static string GetSessionId(AudioSession Session, BinaryEmulator Instance)
        {
            return Session.Id ??= $"{Session.EndpointId}|{WinSysHelper.ToNtDevicePath(Instance.GuestImagePath)}%b{Session.SessionGuid:B}";
        }

        private static void AttachSession(AudioStream Stream, Guid SessionGuid)
        {
            (string, Guid) Key = (Stream.EndpointId ?? string.Empty, SessionGuid);
            if (!Sessions.TryGetValue(Key, out AudioSession Session))
            {
                Session = new AudioSession
                {
                    EndpointId = Key.Item1,
                    SessionGuid = SessionGuid,
                    GroupingParam = Guid.NewGuid(),
                };

                Sessions[Key] = Session;
            }

            Session.Streams.Add(Stream);
            Stream.Session = Session;
        }

        private static void DetachSession(AudioStream Stream)
        {
            AudioSession Session = Stream.Session;
            Session.Streams.Remove(Stream);
            Stream.Session = null;
            ReleaseSessionIfUnused(Session);
        }

        private static void ReleaseSessionIfUnused(AudioSession Session)
        {
            if (Session.Streams.Count == 0 && Session.Handles <= 0)
                Sessions.Remove((Session.EndpointId, Session.SessionGuid));
        }

        private static void PublishSessionGains(AudioSession Session)
        {
            Span<float> SessionGains = stackalloc float[MixChannels];
            GetSessionGains(Session, SessionGains);

            foreach (AudioStream Stream in Session.Streams)
                (Stream.Engine as AudioStreamEngine)?.SetGains(Stream.ChannelVolumes, SessionGains);
        }

        private static void PublishGains(AudioStream Stream)
        {
            Span<float> SessionGains = stackalloc float[MixChannels];
            GetSessionGains(Stream.Session, SessionGains);
            (Stream.Engine as AudioStreamEngine)?.SetGains(Stream.ChannelVolumes, SessionGains);
        }

        private static void GetSessionGains(AudioSession Session, Span<float> Gains)
        {
            float Master = Session.MuteValue != 0 ? 0f : Session.Volume;
            for (int Channel = 0; Channel < Gains.Length; Channel++)
                Gains[Channel] = Master * Session.ChannelVolumes[Channel];
        }

        private static byte[] DeriveStreamCategory(in LrpcMessage Message)
        {
            Ndr20Reader Reader = new Ndr20Reader(Message.StubData);
            if (!Reader.TryReadUInt16(out ushort Category) || !Reader.TryReadUInt32(out uint RawCategory))
                return LrpcPacket.BuildFault(Message, RpcXBadStubData);

            bool Valid = Category <= StreamCategoryMax && RawCategory <= RawStreamCategoryMax && (Category == 0 || RawCategory == 0);
            uint Derived = !Valid ? 0 : Category == 0 ? RawCategory : DerivedStreamCategories[Category];

            Ndr20Writer Writer = new Ndr20Writer(16);
            Writer.WriteUInt32(Derived);
            Writer.WriteInt32(Valid ? 0 : EInvalidArg);
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

        // camsvc answers the audiosrv microphone check from the consent store. Only an explicit Deny in one of
        // these keys refuses a desktop process.
        private static bool IsMicrophoneAllowed(BinaryEmulator Instance)
        {
            string UserKey = "\\Registry\\User\\" + Instance.WinHelper.CurrentUserSid + MicrophoneConsentKey;

            return !IsConsentDenied(Instance, "\\Registry\\Machine" + MicrophoneConsentKey)
                && !IsConsentDenied(Instance, UserKey)
                && !IsConsentDenied(Instance, UserKey + "\\NonPackaged");
        }

        private static bool IsConsentDenied(BinaryEmulator Instance, string KeyPath)
        {
            if (!Instance.WinHelper.TryReadRegistryValue(KeyPath, "Value", out ValueNode Value) || Value.Data == null)
                return false;

            return MemoryMarshal.Cast<byte, char>(Value.Data).TrimEnd('\0').Equals(ConsentDenied, StringComparison.OrdinalIgnoreCase);
        }

        private static bool TryReadLevels(ref Ndr20Reader Reader, uint Count, out ReadOnlySpan<float> Levels)
        {
            Levels = default;
            if (!Reader.TryReadUInt32(out uint Conformance) || Conformance != Count || Count > int.MaxValue / sizeof(float))
                return false;

            if (!Reader.TryReadBytes((int)Count * sizeof(float), out ReadOnlySpan<byte> Bytes))
                return false;

            Levels = MemoryMarshal.Cast<byte, float>(Bytes);
            return true;
        }

        private static void WriteLevels(ref Ndr20Writer Writer, uint Count, float[] Levels)
        {
            Writer.WriteUInt32(Count);
            for (int Index = 0; Index < Count; Index++)
                Writer.WriteFloat(Levels == null ? 0f : Levels[Index]);
        }

        private static int StoreLevel(float[] Volumes, uint Index, float Level, out bool Unchanged)
        {
            Unchanged = false;
            if (!IsValidLevel(Level) || Index >= Volumes.Length)
                return EInvalidArg;

            Unchanged = Volumes[Index] == Level;
            Volumes[Index] = Level;
            return 0;
        }

        private static int StoreLevels(float[] Volumes, ReadOnlySpan<float> Levels, out bool Changed)
        {
            Changed = false;
            if (Levels.Length != Volumes.Length)
                return EInvalidArg;

            foreach (float Level in Levels)
            {
                if (!IsValidLevel(Level))
                    return EInvalidArg;
            }

            for (int Index = 0; Index < Levels.Length; Index++)
            {
                Changed |= Volumes[Index] != Levels[Index];
                Volumes[Index] = Levels[Index];
            }

            return 0;
        }

        private static bool IsValidLevel(float Level) => Level >= 0f && Level <= 1f;

        private static bool TrySkipVadServerSettings(ref Ndr20Reader Reader)
        {
            Reader.Align(8);
            if (!Reader.TryReadBytes(VadServerSettingsWireSize, out ReadOnlySpan<byte> Settings))
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Settings.Slice(VadSettingsBlobPointerOffset, 4)) == 0)
                return true;

            uint BlobBytes = BinaryPrimitives.ReadUInt32LittleEndian(Settings.Slice(VadSettingsBlobCountOffset, 4));
            return Reader.TryReadUInt32(out uint Conformance)
                && Conformance == BlobBytes
                && BlobBytes <= int.MaxValue
                && Reader.TrySkip((int)BlobBytes);
        }

        private static void WriteSystemAudioStream(ref Ndr20Writer Writer, AudioStream Stream, int SectionIndex)
        {
            Writer.AlignTo(8);
            Writer.WriteGuid(Stream == null ? Guid.Empty : Stream.Capture ? CaptureEndpointClass : RenderEndpointClass);
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
            Writer.WriteUInt32(Stream == null ? 0u : 1u);
            Writer.WriteUInt32(Stream?.PeriodFrames ?? 0);
            Writer.WriteFloat(Stream?.Format.SampleRate ?? 0);
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

        private static uint SectionBytes(AudioStream Stream)
        {
            return Stream.Capture
                ? Stream.QueueOffset + Stream.QueueCount * AudioCaptureEngine.QueueItemSize
                : RingBufferOffset + Stream.RingBytes;
        }

        private static bool TryCreateSharedBuffer(BinaryEmulator Instance, AudioStream Stream)
        {
            ulong SectionSize = SectionBytes(Stream);

            ulong Backing = Instance.MapUniqueAddress(SectionSize, MemoryProtection.ReadWrite);
            if (Backing == 0)
                return false;

            Stream.ControlBlock = Backing;
            WriteStreamControlBlock(Instance, Stream);
            PublishHandlePort(Instance, Stream);

            Stream.SectionHandle = Instance.WinHelper.CreateSectionHandle(
                null, SectionSize, PageReadWrite, 0, null, Backing,
                AccessMask.StandardRightsAll | AccessMask.SectionMapRead | AccessMask.SectionMapWrite).Handle;

            HoldServerSectionReference(Instance, Stream);

            // The engine walks the ring from a host thread, so it needs a host pointer into the section
            // rather than the emulator's memory accessors, which are only safe from the guest thread.
            IntPtr Host = Instance.GetHostPointer(Backing, SectionSize);
            if (Host == IntPtr.Zero)
            {
                Log(Instance, "no host pointer for the shared section; stream will not run.");
                return true;
            }

            if (Stream.Capture)
            {
                Stream.Engine = new AudioCaptureEngine(Instance, Host, RingBufferOffset, Stream.RingBytes,
                    Stream.QueueOffset, Stream.QueueCount, Stream.PeriodFrames, Stream.Format);
                Log(Instance, $"stream {Stream.Id} capture engine started.");
                return true;
            }

            AudioStreamEngine Engine = new AudioStreamEngine(
                Instance, Host, RingBufferOffset, Stream.RingBytes, Stream.Format,
                new AudioSinkFormat(MixSampleRate, MixChannels, MixBitsPerSample));

            Stream.Engine = Engine;
            Log(Instance, $"stream {Stream.Id} engine started on the {Engine.Backend} backend.");
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

        private static uint FramesForDuration(ulong DurationHns, uint SampleRate, uint MaxFrames)
        {
            ulong MaxDurationHns = (ulong)MaxFrames * HundredNanosecondsPerSecond / SampleRate;

            if (DurationHns >= MaxDurationHns)
                return MaxFrames;

            ulong Frames = DurationHns * SampleRate / HundredNanosecondsPerSecond;
            return Frames == 0 ? 1 : (uint)Frames;
        }

        private static void WriteStreamControlBlock(BinaryEmulator Instance, AudioStream Stream)
        {
            uint BufferEnd = RingBufferOffset + Stream.RingBytes;
            Span<byte> Block = stackalloc byte[OffWaveFormat + WaveFormat.MaxEncodedSize];

            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffVersion), ControlDataVersion);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffTotalSize), SectionBytes(Stream));
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffMagic), ControlDataMagic);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffSecondaryQueueOffset), NoSecondaryQueue);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(AudioEngine.OffPositionRecord0 + AudioEngine.OffPositionRecordFlags), AudioEngine.PositionContinuous);

            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffStaticSize), StaticControlDataSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffQueueCount), Stream.QueueCount);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffQueueOffset), Stream.QueueOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffBufferStart), RingBufferOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffBufferEnd), BufferEnd);
            BinaryPrimitives.WriteUInt32LittleEndian(Block.Slice(OffBufferLimit), BufferEnd);

            int FormatBytes = Stream.Format.Encode(Block.Slice(OffWaveFormat));

            Instance.WriteMemory(Stream.ControlBlock, Block.Slice(0, OffWaveFormat + FormatBytes));
        }

        private static void WriteCookie(ref Ndr20Writer Writer, uint Magic, uint Id)
        {
            Span<byte> Cookie = stackalloc byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(Cookie, Magic);
            BinaryPrimitives.WriteUInt32LittleEndian(Cookie.Slice(4), Id);
            Writer.WriteContextHandle(Cookie);
        }

        private static bool TryReadCookieId(ReadOnlySpan<byte> Cookie, uint Magic, out uint Id)
        {
            Id = 0;
            if (Cookie.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(Cookie) != Magic)
                return false;

            Id = BinaryPrimitives.ReadUInt32LittleEndian(Cookie.Slice(4, 4));
            return true;
        }

        private static bool TryGetSession(ReadOnlySpan<byte> Cookie, out uint Handle, out AudioSession Session)
        {
            Session = null;
            return TryReadCookieId(Cookie, SessionCookieMagic, out Handle) && SessionHandles.TryGetValue(Handle, out Session);
        }

        private static bool TryGetStream(ReadOnlySpan<byte> Cookie, out AudioStream Stream)
        {
            Stream = null;
            return TryReadCookieId(Cookie, ContextCookieMagic, out uint Id) && Streams.TryGetValue(Id, out Stream);
        }

        private static bool TryFindActiveEndpoint(BinaryEmulator Instance, string Direction, out string EndpointId)
        {
            return ScanActiveEndpoints(Instance, Direction, true, out EndpointId) > 0;
        }

        private static int ScanActiveEndpoints(BinaryEmulator Instance, string Direction, bool StopAtFirst, out string First)
        {
            First = null;
            WinSysHelper Helper = Instance.WinHelper;
            string DirectionKey = MMDevicesKey + "\\" + Direction;

            WinRegKey Root = Helper.ResolveRegistryKey(DirectionKey);
            if (Root == null || !Helper.TryCollectRegistrySubKeyNames(Root, out List<string> Names))
                return 0;

            int Count = 0;
            foreach (string Name in Names)
            {
                if (!IsEndpointActive(Helper, DirectionKey + "\\" + Name))
                    continue;

                First ??= Name;
                Count++;

                if (StopAtFirst)
                    break;
            }

            return Count;
        }

        private static bool IsEndpointActive(WinSysHelper Helper, string EndpointKey)
        {
            return Helper.TryReadRegistryValue(EndpointKey, "DeviceState", out ValueNode State)
                && State.Data != null
                && State.Data.Length >= 4
                && BinaryPrimitives.ReadUInt32LittleEndian(State.Data) == DeviceStateActive;
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

        private static void Log(BinaryEmulator Instance, [InterpolatedStringHandlerArgument(nameof(Instance))] ref LogText Text)
        {
            if (Text.Enabled)
                Instance.TriggerEventMessage("[AudioSrv] " + Text.ToStringAndClear(), LogFlags.General);
        }

        [InterpolatedStringHandler]
        private ref struct LogText
        {
            public readonly bool Enabled;
            private DefaultInterpolatedStringHandler Builder;

            public LogText(int LiteralLength, int FormattedCount, BinaryEmulator Instance, out bool ShouldAppend)
            {
                Enabled = ShouldAppend = (Instance.Settings.Flags & LogFlags.General) != 0;
                Builder = Enabled ? new DefaultInterpolatedStringHandler(LiteralLength, FormattedCount) : default;
            }

            public void AppendLiteral(string Value) => Builder.AppendLiteral(Value);

            public void AppendFormatted<T>(T Value) => Builder.AppendFormatted(Value);

            // The compiler passes the format by this exact parameter name.
            public void AppendFormatted<T>(T Value, string format) => Builder.AppendFormatted(Value, format);

            public string ToStringAndClear() => Builder.ToStringAndClear();
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

    internal enum AudioSampleType
    {
        None,
        UInt8,
        Int16,
        Int24,
        Int32,
        Float32,
    }

    /// <summary>
    /// A WAVEFORMATEX with its WAVEFORMATEXTENSIBLE tail. The checks follow audiosrv's
    /// ValidateWaveFormatEx, ValidateUncompressedWaveFormatEx and ConvertPCMWfxToIEEEFloat.
    /// </summary>
    internal readonly struct WaveFormat
    {
        public const ushort TagExtensible = 0xFFFE;
        public const ushort ExtensibleTailSize = 22;
        public const int MaxEncodedSize = HeaderSize + ExtensibleTailSize;
        private const ushort TagPcm = 1;
        private const ushort TagIeeeFloat = 3;
        private const int HeaderSize = 18;
        private const ushort MaxExtraSize = 0x400;

        private static readonly Guid SubtypePcm = new Guid("00000001-0000-0010-8000-00aa00389b71");
        public static readonly Guid SubtypeIeeeFloat = new Guid("00000003-0000-0010-8000-00aa00389b71");

        public readonly ushort Tag;
        public readonly ushort Channels;
        public readonly uint SampleRate;
        public readonly uint AvgBytesPerSec;
        public readonly ushort BlockAlign;
        public readonly ushort BitsPerSample;
        public readonly ushort ExtraSize;
        public readonly ushort ValidBitsPerSample;
        public readonly uint ChannelMask;
        public readonly Guid SubFormat;

        private WaveFormat(ushort Tag, ushort Channels, uint SampleRate, uint AvgBytesPerSec, ushort BlockAlign, ushort BitsPerSample,
            ushort ExtraSize, ushort ValidBitsPerSample, uint ChannelMask, Guid SubFormat)
        {
            this.Tag = Tag;
            this.Channels = Channels;
            this.SampleRate = SampleRate;
            this.AvgBytesPerSec = AvgBytesPerSec;
            this.BlockAlign = BlockAlign;
            this.BitsPerSample = BitsPerSample;
            this.ExtraSize = ExtraSize;
            this.ValidBitsPerSample = ValidBitsPerSample;
            this.ChannelMask = ChannelMask;
            this.SubFormat = SubFormat;
        }

        public static WaveFormat Extensible(ushort Channels, uint SampleRate, ushort BitsPerSample, ushort ValidBitsPerSample, uint ChannelMask, Guid SubFormat)
        {
            ushort BlockAlign = (ushort)(Channels * BitsPerSample / 8);
            return new WaveFormat(TagExtensible, Channels, SampleRate, SampleRate * BlockAlign, BlockAlign, BitsPerSample,
                ExtensibleTailSize, ValidBitsPerSample, ChannelMask, SubFormat);
        }

        public static bool TryRead(ref Ndr20Reader Reader, out WaveFormat Format)
        {
            Format = default;

            if (!Reader.TryReadUInt32(out uint Conformance) || !Reader.TryReadBytes(HeaderSize, out ReadOnlySpan<byte> Header))
                return false;

            ushort ExtraSize = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(16, 2));
            if (Conformance != ExtraSize || !Reader.TryReadBytes(ExtraSize, out ReadOnlySpan<byte> Extra))
                return false;

            ushort ValidBits = 0;
            uint ChannelMask = 0;
            Guid SubFormat = Guid.Empty;

            if (ExtraSize >= ExtensibleTailSize)
            {
                ValidBits = BinaryPrimitives.ReadUInt16LittleEndian(Extra.Slice(0, 2));
                ChannelMask = BinaryPrimitives.ReadUInt32LittleEndian(Extra.Slice(2, 4));
                SubFormat = new Guid(Extra.Slice(6, 16));
            }

            Format = new WaveFormat(
                BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0, 2)),
                BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(2, 2)),
                BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(4, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(8, 4)),
                BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(12, 2)),
                BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(14, 2)),
                ExtraSize, ValidBits, ChannelMask, SubFormat);

            return true;
        }

        private bool IsPlainPcmOrFloat => Tag == TagPcm || Tag == TagIeeeFloat;

        private bool HasExtensibleTail => Tag == TagExtensible && ExtraSize >= ExtensibleTailSize;

        private ushort SampleValidBits => HasExtensibleTail ? ValidBitsPerSample : BitsPerSample;

        public bool IsFloat => Tag == TagIeeeFloat || (HasExtensibleTail && SubFormat == SubtypeIeeeFloat);

        public bool IsPcm => Tag == TagPcm || (HasExtensibleTail && SubFormat == SubtypePcm);

        /// <summary>
        /// The sample type the engine converts from, or None. IsFormatSupported accepts more than this, and
        /// Initialize then refuses the rest.
        /// </summary>
        public AudioSampleType SampleType
        {
            get
            {
                if (IsFloat)
                    return BitsPerSample == 32 && SampleValidBits == 32 ? AudioSampleType.Float32 : AudioSampleType.None;

                if (!IsPcm)
                    return AudioSampleType.None;

                if (SampleValidBits != BitsPerSample)
                    return BitsPerSample == 32 && SampleValidBits == 24 ? AudioSampleType.Int32 : AudioSampleType.None;

                return BitsPerSample switch
                {
                    8 => AudioSampleType.UInt8,
                    16 => AudioSampleType.Int16,
                    24 => AudioSampleType.Int24,
                    32 => AudioSampleType.Int32,
                    _ => AudioSampleType.None,
                };
            }
        }

        public bool IsValid() => Check(false);

        public bool IsValidUncompressed() => Check(true);

        private bool Check(bool Uncompressed)
        {
            if (Channels == 0 || SampleRate == 0 || AvgBytesPerSec == 0 || BlockAlign == 0 || ExtraSize > MaxExtraSize)
                return false;

            if (IsPlainPcmOrFloat)
                return ExtraSize == 0 && (BitsPerSample & 7) == 0 && Channels <= 2 && AvgBytesPerSec == PackedBytesPerSecond;

            if (Tag != TagExtensible)
                return !Uncompressed;

            if (ExtraSize < ExtensibleTailSize)
                return false;

            bool Pcm = SubFormat == SubtypePcm;
            if (!Pcm && SubFormat != SubtypeIeeeFloat)
                return !Uncompressed;

            bool DepthValid = Pcm
                ? ((ushort)(BitsPerSample - 8) & 0xFFE7) == 0
                : BitsPerSample == 32 || BitsPerSample == 64;

            return DepthValid
                && ValidBitsPerSample != 0
                && BitsPerSample >= ValidBitsPerSample
                && AvgBytesPerSec == PackedBytesPerSecond
                && BlockAlign == BitsPerSample * Channels / 8;
        }

        private uint PackedBytesPerSecond => unchecked(SampleRate * BitsPerSample * Channels) >> 3;

        public WaveFormat ConvertPcmToFloat()
        {
            bool PlainPcm = Tag == TagPcm;
            bool ExtensiblePcm = Tag == TagExtensible && SubFormat == SubtypePcm && (ValidBitsPerSample & 7) == 0;
            if (!PlainPcm && !ExtensiblePcm)
                return this;

            ushort FloatBlockAlign = (ushort)(Channels * 4);
            return new WaveFormat(PlainPcm ? TagIeeeFloat : TagExtensible, Channels, SampleRate, unchecked(SampleRate * FloatBlockAlign),
                FloatBlockAlign, 32, ExtraSize, PlainPcm ? ValidBitsPerSample : (ushort)32, ChannelMask,
                PlainPcm ? SubFormat : SubtypeIeeeFloat);
        }

        public int Encode(Span<byte> Bytes)
        {
            ushort Extra = HasExtensibleTail ? ExtensibleTailSize : (ushort)0;

            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(0, 2), Tag);
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(2, 2), Channels);
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(4, 4), SampleRate);
            BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(8, 4), AvgBytesPerSec);
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(12, 2), BlockAlign);
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(14, 2), BitsPerSample);
            BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(16, 2), Extra);

            if (Extra != 0)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Bytes.Slice(18, 2), ValidBitsPerSample);
                BinaryPrimitives.WriteUInt32LittleEndian(Bytes.Slice(20, 4), ChannelMask);
                SubFormat.TryWriteBytes(Bytes.Slice(24, 16));
            }

            return HeaderSize + Extra;
        }

        public void WriteUnique(ref Ndr20Writer Writer)
        {
            Span<byte> Bytes = stackalloc byte[MaxEncodedSize];
            int Length = Encode(Bytes);

            Writer.WriteUniqueReferent();
            Writer.WriteUInt32((uint)(Length - HeaderSize));
            Writer.WriteBytes(Bytes.Slice(0, Length));
            Writer.AlignTo(4);
        }

        public override string ToString()
        {
            string Kind = IsFloat ? "float" : IsPcm ? "pcm" : $"tag 0x{Tag:X}";
            return $"{Kind} {BitsPerSample}/{SampleValidBits} {Channels}ch {SampleRate}Hz align {BlockAlign}";
        }
    }
}
