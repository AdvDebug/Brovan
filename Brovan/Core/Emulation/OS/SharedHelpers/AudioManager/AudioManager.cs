using System;
using System.Diagnostics;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    /// <summary>
    /// A host playback device. <see cref="Write"/> blocks until the device has taken the samples.
    /// </summary>
    public interface IAudioSink : IDisposable
    {
        void Write(ReadOnlySpan<byte> Samples);
    }

    public readonly struct AudioSinkFormat
    {
        public readonly uint SampleRate;
        public readonly ushort Channels;
        public readonly ushort BitsPerSample;

        public AudioSinkFormat(uint SampleRate, ushort Channels, ushort BitsPerSample)
        {
            this.SampleRate = SampleRate;
            this.Channels = Channels;
            this.BitsPerSample = BitsPerSample;
        }

        public int BlockAlign => Channels * (BitsPerSample / 8);

        public int BytesPerSecond => (int)SampleRate * BlockAlign;
    }

    public static class AudioSinkFactory
    {
        public static IAudioSink Create(AudioSinkFormat Format, out string Backend)
        {
            try
            {
                if (Android.AndroidHost.IsActive)
                {
                    Backend = "AAudio";
                    return new Android.AndroidAudioSink(Format);
                }

                if (OperatingSystem.IsWindows())
                {
                    Backend = "waveOut";
                    return new WindowsAudioSink(Format);
                }

                if (OperatingSystem.IsLinux())
                {
                    Backend = "ALSA";
                    return new LinuxAudioSink(Format);
                }
            }
            catch (Exception)
            {
            }

            Backend = "silent";
            return new SilentAudioSink(Format);
        }
    }

    /// <summary>
    /// Used when the host has no usable device. It still has to consume at real time, because the guest's
    /// ring only drains as fast as the sink accepts.
    /// </summary>
    internal sealed class SilentAudioSink : IAudioSink
    {
        private readonly AudioSinkFormat Format;
        private readonly Stopwatch Elapsed = Stopwatch.StartNew();
        private long WrittenBytes;

        public SilentAudioSink(AudioSinkFormat Format)
        {
            this.Format = Format;
        }

        public void Write(ReadOnlySpan<byte> Samples)
        {
            WrittenBytes += Samples.Length;

            long DueMs = WrittenBytes * 1000 / Format.BytesPerSecond;
            long BehindMs = DueMs - Elapsed.ElapsedMilliseconds;
            if (BehindMs > 0)
                Thread.Sleep((int)Math.Min(BehindMs, 100));
        }

        public void Dispose()
        {
        }
    }
}
