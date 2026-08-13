using System;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    internal sealed class AudioStreamEngine : IDisposable
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

            Sink = AudioSinkFactory.Create(Format, out string SinkBackend);
            Backend = SinkBackend;

            int ChunkBytes = Format.BytesPerSecond * ChunkMilliseconds / 1000 / Format.BlockAlign * Format.BlockAlign;
            Chunk = new byte[ChunkBytes];
            Silence = new byte[ChunkBytes];

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

            while (!Stopping)
            {
                if ((*(uint*)(Base + OffVolatileFlags) & FlagRunning) == 0)
                {
                    Thread.Sleep(IdleSleepMilliseconds);
                    continue;
                }

                long Written = Interlocked.CompareExchange(ref *(long*)(Base + OffClientCursor), 0, 0);
                long Read = *(long*)(Base + OffServerCursor);
                long Available = Written - Read;

                // Feed the device anyway when the guest is behind, both to keep it from underrunning and
                // because the write is what advances real time for this loop.
                if (Available <= 0)
                {
                    Sink.Write(Silence);
                    SignalPeriod();
                    continue;
                }

                int Take = (int)Math.Min(Available, Chunk.Length);
                int Offset = (int)(Read % RingBytes);
                int Contiguous = Math.Min(Take, (int)RingBytes - Offset);

                new ReadOnlySpan<byte>(Base + BufferStart + Offset, Contiguous).CopyTo(Chunk);
                if (Contiguous < Take)
                    new ReadOnlySpan<byte>(Base + BufferStart, Take - Contiguous).CopyTo(Chunk.AsSpan(Contiguous));

                Sink.Write(Chunk.AsSpan(0, Take));

                Interlocked.Exchange(ref *(long*)(Base + OffServerCursor), Read + Take);
                RenderedBytes += Take;
                SignalPeriod();
            }
        }

        private void SignalPeriod()
        {
            WinEvent Event = PeriodEvent;
            if (Event != null)
                Event.Signaled = true;
        }

        public void Dispose()
        {
            if (Stopping)
                return;

            Stopping = true;
            Worker.Join(StopTimeoutMilliseconds);
            Sink.Dispose();
        }
    }
}
