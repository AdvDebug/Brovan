using System;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal sealed unsafe class AndroidAudioSink : IAudioSink
    {
        private const int FormatPcmFloat = 2;
        private const int PerformanceModeLowLatency = 12;
        private const long WriteTimeoutNanoseconds = 1_000_000_000;

        [DllImport("libaaudio.so")]
        private static extern int AAudio_createStreamBuilder(out IntPtr Builder);

        [DllImport("libaaudio.so")]
        private static extern void AAudioStreamBuilder_setFormat(IntPtr Builder, int Format);

        [DllImport("libaaudio.so")]
        private static extern void AAudioStreamBuilder_setChannelCount(IntPtr Builder, int Channels);

        [DllImport("libaaudio.so")]
        private static extern void AAudioStreamBuilder_setSampleRate(IntPtr Builder, int SampleRate);

        [DllImport("libaaudio.so")]
        private static extern void AAudioStreamBuilder_setPerformanceMode(IntPtr Builder, int Mode);

        [DllImport("libaaudio.so")]
        private static extern int AAudioStreamBuilder_openStream(IntPtr Builder, out IntPtr Stream);

        [DllImport("libaaudio.so")]
        private static extern int AAudioStreamBuilder_delete(IntPtr Builder);

        [DllImport("libaaudio.so")]
        private static extern int AAudioStream_requestStart(IntPtr Stream);

        [DllImport("libaaudio.so")]
        private static extern int AAudioStream_write(IntPtr Stream, void* Buffer, int Frames, long TimeoutNanoseconds);

        [DllImport("libaaudio.so")]
        private static extern long AAudioStream_getFramesWritten(IntPtr Stream);

        [DllImport("libaaudio.so")]
        private static extern long AAudioStream_getFramesRead(IntPtr Stream);

        [DllImport("libaaudio.so")]
        private static extern int AAudioStream_close(IntPtr Stream);

        private readonly int BlockAlign;
        private IntPtr Stream;

        public AndroidAudioSink(AudioSinkFormat Format)
        {
            BlockAlign = Format.BlockAlign;

            if (AAudio_createStreamBuilder(out IntPtr Builder) != 0 || Builder == IntPtr.Zero)
                throw new InvalidOperationException("AAudio_createStreamBuilder failed.");

            try
            {
                AAudioStreamBuilder_setFormat(Builder, FormatPcmFloat);
                AAudioStreamBuilder_setChannelCount(Builder, Format.Channels);
                AAudioStreamBuilder_setSampleRate(Builder, (int)Format.SampleRate);
                AAudioStreamBuilder_setPerformanceMode(Builder, PerformanceModeLowLatency);

                if (AAudioStreamBuilder_openStream(Builder, out Stream) != 0 || Stream == IntPtr.Zero)
                    throw new InvalidOperationException("AAudioStreamBuilder_openStream failed.");
            }
            finally
            {
                AAudioStreamBuilder_delete(Builder);
            }

            AAudioStream_requestStart(Stream);
        }

        public int QueuedBytes
        {
            get
            {
                if (Stream == IntPtr.Zero)
                    return 0;

                long Frames = AAudioStream_getFramesWritten(Stream) - AAudioStream_getFramesRead(Stream);
                if (Frames <= 0)
                    return 0;

                return (int)Math.Min(Frames * BlockAlign, int.MaxValue);
            }
        }

        public void WaitForProgress(int TimeoutMilliseconds) => System.Threading.Thread.Sleep(TimeoutMilliseconds);

        public void Write(ReadOnlySpan<byte> Samples)
        {
            if (Stream == IntPtr.Zero)
                return;

            fixed (byte* Base = Samples)
            {
                int Offset = 0;
                while (Offset < Samples.Length)
                {
                    int Frames = (Samples.Length - Offset) / BlockAlign;
                    if (Frames == 0)
                        return;

                    int Written = AAudioStream_write(Stream, Base + Offset, Frames, WriteTimeoutNanoseconds);
                    if (Written <= 0)
                        return;

                    Offset += Written * BlockAlign;
                }
            }
        }

        public void Dispose()
        {
            if (Stream == IntPtr.Zero)
                return;

            AAudioStream_close(Stream);
            Stream = IntPtr.Zero;
        }
    }
}
