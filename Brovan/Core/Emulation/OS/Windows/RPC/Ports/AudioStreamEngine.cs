using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal abstract class AudioEngine
    {
        internal const int OffPositionRecord0 = 0x028;
        internal const int OffPositionRecordFlags = 0x24;
        internal const uint PositionContinuous = 2;

        protected const int OffQueueRead = 0x008;
        protected const int OffQueueWrite = 0x00C;
        protected const int OffClientCursor = 0x018;
        protected const int OffServerCursor = 0x020;
        protected const int IdleWaitMilliseconds = 5;

        private const int StopTimeoutMilliseconds = 200;
        private const int OffVolatileFlags = 0x0AC;
        private const int OffPositionRecord1 = 0x050;
        private const int OffStartPosition = 0x078;
        private const int OffStartPadding = 0x088;
        private const int OffStartQpc = 0x090;
        private const int OffStartBytes = 0x0A0;
        private const int OffPositionSelector = 0x0A8;
        private const int FlagRunning = 0x1;
        private const int FlagStartLatched = 0x2;
        private const int FlagsTimestamped = 0x6;

        protected readonly IntPtr Block;
        private readonly BinaryEmulator Instance;
        private readonly Thread Worker;
        private readonly ManualResetEventSlim StopRequested = new ManualResetEventSlim(false, 0);

        private volatile WinEvent PeriodEvent;

        public long TransferredBytes { get; protected set; }

        protected AudioEngine(BinaryEmulator Instance, IntPtr Block, string ThreadName)
        {
            this.Instance = Instance;
            this.Block = Block;

            Worker = new Thread(Run)
            {
                IsBackground = true,
                Priority = ThreadPriority.AboveNormal,
                Name = ThreadName,
            };
        }

        /// <summary>
        /// Called last by the derived constructor, so the worker never sees a partly built engine.
        /// </summary>
        protected void StartWorker() => Worker.Start();

        protected abstract void Run();

        public void SetPeriodEvent(WinEvent Event) => PeriodEvent = Event;

        protected bool Stopping => StopRequested.IsSet;

        protected unsafe bool StreamRunning => (Volatile.Read(ref *(int*)((byte*)Block + OffVolatileFlags)) & FlagRunning) != 0;

        protected void Pause(int Milliseconds) => StopRequested.Wait(Milliseconds);

        protected void SignalPeriod()
        {
            WinEvent Event = PeriodEvent;
            if (Event != null)
                Event.Signaled = true;
        }

        // The guest QPC runs at 10 MHz, so its counts are already the 100 ns units a position record holds.
        protected long GuestQpc() => (long)Instance.GetEmulatedPerformanceCounter();

        /// <summary>
        /// The engine side of CCrossProcessBaseEndpoint::SetCurrentTimeStamp. The position goes into the record
        /// the client is not reading, then the selector flips.
        /// </summary>
        protected unsafe void PublishPosition(ulong Position, float SampleRate, int BlockAlign, long Qpc)
        {
            byte* Base = (byte*)Block;
            int Selector = Volatile.Read(ref *(int*)(Base + OffPositionSelector));

            WritePositionRecord(Base + (Selector == 0 ? OffPositionRecord1 : OffPositionRecord0), Position, Qpc, SampleRate, PositionContinuous);
            Interlocked.Exchange(ref *(int*)(Base + OffPositionSelector), Selector == 0 ? 1 : 0);

            int Flags = Volatile.Read(ref *(int*)(Base + OffVolatileFlags));
            if ((Flags & FlagStartLatched) != 0)
                return;

            *(ulong*)(Base + OffStartPosition) = Position;
            *(ulong*)(Base + OffStartPadding) = 0;
            *(long*)(Base + OffStartQpc) = Qpc;
            Interlocked.Exchange(ref *(long*)(Base + OffStartBytes), (long)Position * BlockAlign);
            Interlocked.Or(ref *(int*)(Base + OffVolatileFlags), FlagsTimestamped);
        }

        protected static unsafe void WritePositionRecord(byte* Record, ulong Position, long Qpc, float SampleRate, uint Flags)
        {
            *(ulong*)(Record + 0x00) = Position;
            *(ulong*)(Record + 0x08) = Position;
            *(ulong*)(Record + 0x10) = 0;
            *(long*)(Record + 0x18) = Qpc;
            *(float*)(Record + 0x20) = SampleRate;
            *(uint*)(Record + OffPositionRecordFlags) = Flags;
        }

        /// <summary>
        /// Returns false when the worker is still running, which means the guest memory it uses must stay mapped.
        /// </summary>
        public bool Stop()
        {
            StopRequested.Set();
            return Worker.Join(StopTimeoutMilliseconds);
        }
    }

    internal sealed class AudioStreamEngine : AudioEngine
    {
        private const int ChunkMilliseconds = 10;
        private const int StarveWaitMilliseconds = 4;
        private const int QueueFloorMilliseconds = 20;
        private const int MaxChunkBytes = 256 * 1024;

        private readonly uint BufferStart;
        private readonly uint RingBytes;
        private readonly int BlockAlign;
        private readonly float SampleRate;
        private readonly double StreamFramesPerSinkByte;
        private readonly int MaxTake;
        private readonly int QueueFloorBytes;
        private readonly IAudioSink Sink;
        private readonly AudioSampleConverter Converter;
        private readonly byte[] Chunk;
        private readonly byte[] Silence;

        private volatile AudioGains Gains;

        public string Backend { get; }

        public void SetGains(ReadOnlySpan<float> StreamGains, ReadOnlySpan<float> SessionGains) =>
            Gains = Converter.CreateGains(StreamGains, SessionGains);

        public AudioStreamEngine(BinaryEmulator Instance, IntPtr Block, uint BufferStart, uint RingBytes, in WaveFormat Format, AudioSinkFormat SinkFormat)
            : base(Instance, Block, "Brovan audio engine")
        {
            this.BufferStart = BufferStart;
            this.RingBytes = RingBytes;
            BlockAlign = Format.BlockAlign;
            SampleRate = Format.SampleRate;
            StreamFramesPerSinkByte = (double)Format.SampleRate / SinkFormat.SampleRate / SinkFormat.BlockAlign;

            Sink = AudioSinkFactory.Create(SinkFormat, out string SinkBackend);
            Backend = SinkBackend;

            int ChunkFrames = (int)Math.Clamp(Format.SampleRate * ChunkMilliseconds / 1000, 1, MaxChunkBytes / BlockAlign);
            Chunk = new byte[ChunkFrames * BlockAlign];

            int SinkChunkBytes = SinkFormat.BytesPerSecond * ChunkMilliseconds / 1000 / SinkFormat.BlockAlign * SinkFormat.BlockAlign;
            Silence = new byte[SinkChunkBytes];

            Converter = new AudioSampleConverter(Format, SinkFormat, ChunkFrames);
            Gains = Converter.UnityGains;

            // A ring shorter than one chunk is legal. the buffer duration comes from the client.
            MaxTake = (int)Math.Min((uint)Chunk.Length, RingBytes);
            QueueFloorBytes = SinkFormat.BytesPerSecond * QueueFloorMilliseconds / 1000;

            StartWorker();
        }

        protected override unsafe void Run()
        {
            byte* Base = (byte*)Block;

            // The guest maps the control block writable, so the cursor is published there, never read back.
            long Read = 0;
            long Played = 0;

            // The sink is torn down here rather than in Dispose so that no host device buffer is freed
            // while this thread is still inside Sink.Write.
            try
            {
                while (!Stopping)
                {
                    if (!StreamRunning)
                    {
                        Pause(IdleWaitMilliseconds);
                        continue;
                    }

                    long Written = Interlocked.CompareExchange(ref *(long*)(Base + OffClientCursor), 0, 0);

                    // IAudioClient::Reset zeroes both cursors client side and tells the server nothing.
                    if (Written < Read)
                    {
                        Read = Written;
                        Played = 0;
                        Interlocked.Exchange(ref *(long*)(Base + OffServerCursor), Read);
                    }

                    long Available = Written - Read;

                    int Take = (int)Math.Min(Available, MaxTake);
                    Take -= Take % BlockAlign;

                    if (Take < MaxTake && Sink.QueuedBytes > QueueFloorBytes)
                    {
                        SignalPeriod();
                        Sink.WaitForProgress(StarveWaitMilliseconds);
                        continue;
                    }

                    if (Take <= 0)
                    {
                        Sink.Write(Silence);
                        SignalPeriod();
                        continue;
                    }

                    int Offset = (int)(Read % RingBytes);
                    int Contiguous = Math.Min(Take, (int)RingBytes - Offset);

                    new ReadOnlySpan<byte>(Base + BufferStart + Offset, Contiguous).CopyTo(Chunk);
                    if (Contiguous < Take)
                        new ReadOnlySpan<byte>(Base + BufferStart, Take - Contiguous).CopyTo(Chunk.AsSpan(Contiguous));

                    Sink.Write(Converter.Convert(Chunk.AsSpan(0, Take), Gains));

                    Read += Take;
                    Interlocked.Exchange(ref *(long*)(Base + OffServerCursor), Read);
                    TransferredBytes += Take;

                    long Heard = Read / BlockAlign - (long)(Sink.QueuedBytes * StreamFramesPerSinkByte);
                    Played = Math.Max(Played, Heard);
                    PublishPosition((ulong)Played, SampleRate, BlockAlign, GuestQpc());
                    SignalPeriod();
                }
            }
            finally
            {
                Sink.Dispose();
            }
        }
    }

    internal sealed class AudioCaptureEngine : AudioEngine
    {
        public const int QueueItemSize = 64;

        private const int OffItemBufferOffset = 0x04;
        private const int OffItemType = 0x08;
        private const int OffItemPosition = 0x10;
        private const int OffItemFrames = 0x38;
        private const uint ItemTypeData = 1;
        private const uint PositionDiscontinuous = 1;

        private readonly uint BufferStart;
        private readonly uint RingBytes;
        private readonly uint QueueOffset;
        private readonly uint QueueCount;
        private readonly uint PacketFrames;
        private readonly int PacketBytes;
        private readonly int BlockAlign;
        private readonly float SampleRate;
        private readonly byte SilenceByte;
        private readonly long PacketTicks;

        public AudioCaptureEngine(BinaryEmulator Instance, IntPtr Block, uint BufferStart, uint RingBytes, uint QueueOffset, uint QueueCount, uint PacketFrames, in WaveFormat Format)
            : base(Instance, Block, "Brovan audio capture")
        {
            this.BufferStart = BufferStart;
            this.RingBytes = RingBytes;
            this.QueueOffset = QueueOffset;
            this.QueueCount = QueueCount;
            this.PacketFrames = PacketFrames;
            PacketBytes = (int)PacketFrames * Format.BlockAlign;
            BlockAlign = Format.BlockAlign;
            SampleRate = Format.SampleRate;
            PacketTicks = Math.Max(1, Stopwatch.Frequency * PacketFrames / Format.SampleRate);

            // Unsigned 8-bit PCM is centered on 0x80.
            SilenceByte = Format.SampleType == AudioSampleType.UInt8 ? (byte)0x80 : (byte)0;

            StartWorker();
        }

        protected override unsafe void Run()
        {
            byte* Base = (byte*)Block;
            byte* Queue = Base + QueueOffset;

            long Written = 0;
            long LastConsumed = 0;
            uint WriteIndex = 0;
            ulong DevicePosition = 0;
            bool Discontinuity = false;
            long Due = 0;

            while (!Stopping)
            {
                if (!StreamRunning)
                {
                    Due = 0;
                    Pause(IdleWaitMilliseconds);
                    continue;
                }

                long Now = Stopwatch.GetTimestamp();
                if (Due == 0)
                    Due = Now + PacketTicks;

                if (Now < Due)
                {
                    Pause((int)(((Due - Now) * 1000 + Stopwatch.Frequency - 1) / Stopwatch.Frequency));
                    continue;
                }

                // A stalled host thread resumes at the current packet instead of bursting the backlog.
                if (Now - Due > PacketTicks * 8)
                    Due = Now;

                Due += PacketTicks;

                long Consumed = Interlocked.CompareExchange(ref *(long*)(Base + OffServerCursor), 0, 0);
                uint ReadIndex = Volatile.Read(ref *(uint*)(Base + OffQueueRead));

                // IAudioClient::Reset zeroes the cursors and drains the queue client side.
                if (Consumed < LastConsumed)
                {
                    Written = Consumed - Consumed % PacketBytes;
                    WriteIndex = ReadIndex < QueueCount ? ReadIndex : 0;
                    Volatile.Write(ref *(uint*)(Base + OffQueueWrite), WriteIndex);
                }

                LastConsumed = Consumed;

                long Pending = Written - Consumed;
                uint NextIndex = (WriteIndex + 1) % QueueCount;
                bool Fits = ReadIndex < QueueCount && NextIndex != ReadIndex && Pending >= 0 && Pending <= RingBytes - PacketBytes;
                long Qpc = GuestQpc();

                if (Fits)
                {
                    uint RingOffset = (uint)(Written % RingBytes);
                    new Span<byte>(Base + BufferStart + RingOffset, PacketBytes).Fill(SilenceByte);

                    byte* Item = Queue + (long)WriteIndex * QueueItemSize;
                    new Span<byte>(Item, QueueItemSize).Clear();
                    *(uint*)(Item + OffItemBufferOffset) = BufferStart + RingOffset;
                    *(uint*)(Item + OffItemType) = ItemTypeData;
                    WritePositionRecord(Item + OffItemPosition, DevicePosition, Qpc, SampleRate, Discontinuity ? PositionDiscontinuous : PositionContinuous);
                    *(uint*)(Item + OffItemFrames) = PacketFrames;

                    WriteIndex = NextIndex;
                    Volatile.Write(ref *(uint*)(Base + OffQueueWrite), WriteIndex);

                    Written += PacketBytes;
                    Interlocked.Exchange(ref *(long*)(Base + OffClientCursor), Written);
                    TransferredBytes += PacketBytes;
                    Discontinuity = false;
                }
                else
                {
                    Discontinuity = true;
                }

                DevicePosition += PacketFrames;
                PublishPosition(DevicePosition, SampleRate, BlockAlign, Qpc);
                SignalPeriod();
            }
        }
    }

    /// <summary>
    /// The mix matrix with the stream and session volumes folded in. It is never changed after it is published.
    /// </summary>
    internal sealed class AudioGains
    {
        public readonly float[] Matrix;
        public readonly bool Passthrough;

        public AudioGains(float[] Matrix, bool Passthrough)
        {
            this.Matrix = Matrix;
            this.Passthrough = Passthrough;
        }
    }

    internal sealed class AudioSampleConverter
    {
        internal const uint SpeakerFrontLeft = 0x1;
        internal const uint SpeakerFrontRight = 0x2;
        private const uint SpeakerFrontCenter = 0x4;
        private const uint SpeakerLowFrequency = 0x8;
        private const uint SpeakerBackLeft = 0x10;
        private const uint SpeakerBackRight = 0x20;
        private const uint SpeakerFrontLeftOfCenter = 0x40;
        private const uint SpeakerFrontRightOfCenter = 0x80;
        private const uint SpeakerBackCenter = 0x100;
        private const uint SpeakerSideLeft = 0x200;
        private const uint SpeakerSideRight = 0x400;
        private const uint SpeakerTopCenter = 0x800;
        private const uint SpeakerTopFrontLeft = 0x1000;
        private const uint SpeakerTopFrontCenter = 0x2000;
        private const uint SpeakerTopFrontRight = 0x4000;
        private const uint SpeakerTopBackLeft = 0x8000;
        private const uint SpeakerTopBackCenter = 0x10000;
        private const uint SpeakerTopBackRight = 0x20000;

        private const float SideGain = 0.70710678f;

        private readonly AudioSampleType Type;
        private readonly int SourceChannels;
        private readonly int SampleBytes;
        private readonly int SourceBlockAlign;
        private readonly int SinkChannels;
        private readonly float[] Layout;
        private readonly double Step;
        private readonly float[] Mixed;
        private readonly float[] Resampled;
        private readonly float[] Previous;
        private readonly bool SinkNative;
        private double Phase;

        public AudioGains UnityGains { get; }

        public AudioSampleConverter(in WaveFormat Format, AudioSinkFormat SinkFormat, int MaxFrames)
        {
            SourceChannels = Format.Channels;
            SampleBytes = Format.BitsPerSample / 8;
            SourceBlockAlign = Format.BlockAlign;
            SinkChannels = SinkFormat.Channels;
            Type = Format.SampleType;

            Layout = BuildLayout(Format, SinkChannels);
            Mixed = new float[MaxFrames * SinkChannels];
            Previous = new float[SinkChannels];

            SinkNative = Format.IsFloat
                && Format.BitsPerSample == SinkFormat.BitsPerSample
                && Format.Channels == SinkFormat.Channels
                && Format.SampleRate == SinkFormat.SampleRate;

            UnityGains = new AudioGains(Layout, SinkNative);

            Step = (double)Format.SampleRate / SinkFormat.SampleRate;
            int MaxOutputFrames = (int)Math.Ceiling(MaxFrames / Step) + 2;
            Resampled = Format.SampleRate == SinkFormat.SampleRate ? null : new float[MaxOutputFrames * SinkChannels];
        }

        public AudioGains CreateGains(ReadOnlySpan<float> StreamGains, ReadOnlySpan<float> SessionGains)
        {
            float[] Matrix = new float[Layout.Length];
            bool Unity = true;

            for (int Out = 0; Out < SinkChannels; Out++)
                Unity &= SessionGains[Out] == 1f;

            for (int Channel = 0; Channel < SourceChannels; Channel++)
            {
                Unity &= StreamGains[Channel] == 1f;
                int Row = Channel * SinkChannels;

                for (int Out = 0; Out < SinkChannels; Out++)
                    Matrix[Row + Out] = Layout[Row + Out] * StreamGains[Channel] * SessionGains[Out];
            }

            return new AudioGains(Matrix, SinkNative && Unity);
        }

        public ReadOnlySpan<byte> Convert(ReadOnlySpan<byte> Source, AudioGains Gains)
        {
            if (Gains.Passthrough)
                return Source;

            int Frames = Source.Length / SourceBlockAlign;
            Mix(Source, Frames, Gains.Matrix);

            if (Resampled == null)
                return MemoryMarshal.AsBytes(Mixed.AsSpan(0, Frames * SinkChannels));

            int Produced = Resample(Frames);
            return MemoryMarshal.AsBytes(Resampled.AsSpan(0, Produced * SinkChannels));
        }

        private void Mix(ReadOnlySpan<byte> Source, int Frames, float[] Matrix)
        {
            Span<float> Output = Mixed.AsSpan(0, Frames * SinkChannels);
            Output.Clear();

            for (int Frame = 0; Frame < Frames; Frame++)
            {
                ReadOnlySpan<byte> FrameBytes = Source.Slice(Frame * SourceBlockAlign, SourceBlockAlign);
                Span<float> Target = Output.Slice(Frame * SinkChannels, SinkChannels);

                for (int Channel = 0; Channel < SourceChannels; Channel++)
                {
                    float Sample = ReadSample(FrameBytes.Slice(Channel * SampleBytes, SampleBytes));
                    int Row = Channel * SinkChannels;

                    for (int Out = 0; Out < SinkChannels; Out++)
                        Target[Out] += Sample * Matrix[Row + Out];
                }
            }
        }

        private float ReadSample(ReadOnlySpan<byte> Bytes)
        {
            switch (Type)
            {
                case AudioSampleType.UInt8:
                    return (Bytes[0] - 128) / 128f;

                case AudioSampleType.Int16:
                    return BinaryPrimitives.ReadInt16LittleEndian(Bytes) / 32768f;

                case AudioSampleType.Int24:
                    return ((Bytes[0] | (Bytes[1] << 8) | (Bytes[2] << 16)) << 8 >> 8) / 8388608f;

                case AudioSampleType.Int32:
                    return BinaryPrimitives.ReadInt32LittleEndian(Bytes) / 2147483648f;

                default:
                    return BinaryPrimitives.ReadSingleLittleEndian(Bytes);
            }
        }

        /// <summary>
        /// Interpolates linearly across chunk boundaries. Position 0 is the last frame of the previous chunk.
        /// </summary>
        private int Resample(int Frames)
        {
            int Produced = 0;
            double Position = Phase;

            while (Position < Frames)
            {
                int Index = (int)Position;
                float Fraction = (float)(Position - Index);

                for (int Channel = 0; Channel < SinkChannels; Channel++)
                {
                    float From = Index == 0 ? Previous[Channel] : Mixed[(Index - 1) * SinkChannels + Channel];
                    float To = Mixed[Index * SinkChannels + Channel];
                    Resampled[Produced * SinkChannels + Channel] = From + (To - From) * Fraction;
                }

                Produced++;
                Position += Step;
            }

            Phase = Position - Frames;
            if (Frames > 0)
                Mixed.AsSpan((Frames - 1) * SinkChannels, SinkChannels).CopyTo(Previous);

            return Produced;
        }

        private static float[] BuildLayout(in WaveFormat Format, int SinkChannels)
        {
            float[] Matrix = new float[Format.Channels * SinkChannels];

            if (Format.Channels == 1)
            {
                Array.Fill(Matrix, 1f);
                return Matrix;
            }

            uint Mask = Format.ChannelMask != 0 ? Format.ChannelMask : DefaultChannelMask(Format.Channels);
            int Channel = 0;

            for (int Bit = 0; Bit < 32 && Channel < Format.Channels; Bit++)
            {
                uint Speaker = 1u << Bit;
                if ((Mask & Speaker) == 0)
                    continue;

                (Matrix[Channel * SinkChannels], Matrix[Channel * SinkChannels + 1]) = SpeakerGains(Speaker);
                Channel++;
            }

            return Matrix;
        }

        // A format that names no speaker positions gets the KSAUDIO_SPEAKER_* layout for its channel count.
        private static uint DefaultChannelMask(int Channels)
        {
            return Channels switch
            {
                2 => SpeakerFrontLeft | SpeakerFrontRight,
                3 => SpeakerFrontLeft | SpeakerFrontRight | SpeakerFrontCenter,
                4 => SpeakerFrontLeft | SpeakerFrontRight | SpeakerBackLeft | SpeakerBackRight,
                5 => SpeakerFrontLeft | SpeakerFrontRight | SpeakerFrontCenter | SpeakerBackLeft | SpeakerBackRight,
                6 => SpeakerFrontLeft | SpeakerFrontRight | SpeakerFrontCenter | SpeakerLowFrequency | SpeakerBackLeft | SpeakerBackRight,
                7 => SpeakerFrontLeft | SpeakerFrontRight | SpeakerFrontCenter | SpeakerLowFrequency | SpeakerBackLeft | SpeakerBackRight | SpeakerBackCenter,
                _ => SpeakerFrontLeft | SpeakerFrontRight | SpeakerFrontCenter | SpeakerLowFrequency | SpeakerBackLeft | SpeakerBackRight | SpeakerSideLeft | SpeakerSideRight,
            };
        }

        private static (float Left, float Right) SpeakerGains(uint Speaker)
        {
            return Speaker switch
            {
                SpeakerFrontLeft or SpeakerFrontLeftOfCenter => (1f, 0f),
                SpeakerFrontRight or SpeakerFrontRightOfCenter => (0f, 1f),
                SpeakerBackLeft or SpeakerSideLeft or SpeakerTopFrontLeft or SpeakerTopBackLeft => (SideGain, 0f),
                SpeakerBackRight or SpeakerSideRight or SpeakerTopFrontRight or SpeakerTopBackRight => (0f, SideGain),
                SpeakerFrontCenter or SpeakerBackCenter or SpeakerTopCenter or SpeakerTopFrontCenter or SpeakerTopBackCenter => (SideGain, SideGain),
                _ => (0f, 0f),
            };
        }
    }
}
