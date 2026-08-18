using System;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal sealed class AudioStreamEngine
    {
        private const int IdleSleepMilliseconds = 5;
        private const int ChunkMilliseconds = 10;
        private const int StopTimeoutMilliseconds = 200;
        private const int OffClientCursor = 0x018;
        private const int OffServerCursor = 0x020;
        private const int OffVolatileFlags = 0x0AC;

        private const uint FlagRunning = 1;

        private readonly IntPtr Block;
        private readonly uint BufferStart;
        private readonly uint RingBytes;
        private readonly int BlockAlign;
        private readonly int MaxTake;
        private readonly IAudioSink Sink;
        private readonly byte[] Chunk;
        private readonly byte[] Silence;
        private readonly Thread Worker;

        private volatile bool Stopping;
        private volatile WinEvent PeriodEvent;

        public string Backend { get; }

        public void SetPeriodEvent(WinEvent Event) => PeriodEvent = Event;

        public long RenderedBytes { get; private set; }

        public AudioStreamEngine(IntPtr Block, uint BufferStart, uint RingBytes, AudioSinkFormat Format)
        {
            this.Block = Block;
            this.BufferStart = BufferStart;
            this.RingBytes = RingBytes;
            BlockAlign = Format.BlockAlign;

            Sink = AudioSinkFactory.Create(Format, out string SinkBackend);
            Backend = SinkBackend;

            int ChunkBytes = Format.BytesPerSecond * ChunkMilliseconds / 1000 / Format.BlockAlign * Format.BlockAlign;
            Chunk = new byte[ChunkBytes];
            Silence = new byte[ChunkBytes];

            // A ring shorter than one chunk is legal. the buffer duration comes from the client.
            MaxTake = (int)Math.Min((uint)ChunkBytes, RingBytes);

            Worker = new Thread(Run)
            {
                IsBackground = true,
                Priority = ThreadPriority.AboveNormal,
                Name = "Brovan audio engine",
            };

            Worker.Start();
        }

        private unsafe void Run()
        {
            byte* Base = (byte*)Block;

            // The guest maps the control block writable, so the cursor is published there, never read back.
            long Read = 0;

            // The sink is torn down here rather than in Dispose so that no host device buffer is freed
            // while this thread is still inside Sink.Write.
            try
            {
                while (!Stopping)
                {
                    if ((*(uint*)(Base + OffVolatileFlags) & FlagRunning) == 0)
                    {
                        Thread.Sleep(IdleSleepMilliseconds);
                        continue;
                    }

                    long Written = Interlocked.CompareExchange(ref *(long*)(Base + OffClientCursor), 0, 0);
                    long Available = Written - Read;

                    int Take = (int)Math.Min(Available, MaxTake);
                    Take -= Take % BlockAlign;

                    // Feed the device anyway when the guest is behind, both to keep it from underrunning and
                    // because the write is what advances real time for this loop.
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

                    Sink.Write(Chunk.AsSpan(0, Take));

                    Read += Take;
                    Interlocked.Exchange(ref *(long*)(Base + OffServerCursor), Read);
                    RenderedBytes += Take;
                    SignalPeriod();
                }
            }
            finally
            {
                Sink.Dispose();
            }
        }

        private void SignalPeriod()
        {
            WinEvent Event = PeriodEvent;
            if (Event != null)
                Event.Signaled = true;
        }

        /// <summary>
        /// Returns false when the worker is still running, which means the guest memory it renders from
        /// must stay mapped.
        /// </summary>
        public bool Stop()
        {
            Stopping = true;
            return Worker.Join(StopTimeoutMilliseconds);
        }
    }
}
