using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    [SupportedOSPlatform("linux")]
    internal sealed unsafe class LinuxAudioSink : IAudioSink
    {
        private const int StreamPlayback = 0;
        private const int FormatFloatLe = 14;
        private const int AccessRwInterleaved = 3;
        private const uint LatencyMicroseconds = 100_000;

        [DllImport("libasound.so.2", CharSet = CharSet.Ansi)]
        private static extern int snd_pcm_open(out IntPtr Pcm, string Name, int Stream, int Mode);

        [DllImport("libasound.so.2")]
        private static extern int snd_pcm_set_params(IntPtr Pcm, int Format, int Access, uint Channels, uint Rate, int SoftResample, uint Latency);

        [DllImport("libasound.so.2")]
        private static extern nint snd_pcm_writei(IntPtr Pcm, void* Buffer, nuint Frames);

        [DllImport("libasound.so.2")]
        private static extern int snd_pcm_recover(IntPtr Pcm, int Error, int Silent);

        [DllImport("libasound.so.2")]
        private static extern int snd_pcm_close(IntPtr Pcm);

        private readonly int BlockAlign;
        private IntPtr Pcm;

        public LinuxAudioSink(AudioSinkFormat Format)
        {
            BlockAlign = Format.BlockAlign;

            if (snd_pcm_open(out Pcm, "default", StreamPlayback, 0) < 0)
                throw new InvalidOperationException("snd_pcm_open failed.");

            if (snd_pcm_set_params(Pcm, FormatFloatLe, AccessRwInterleaved, Format.Channels, Format.SampleRate, 1, LatencyMicroseconds) < 0)
            {
                snd_pcm_close(Pcm);
                Pcm = IntPtr.Zero;
                throw new InvalidOperationException("snd_pcm_set_params failed.");
            }
        }

        public void Write(ReadOnlySpan<byte> Samples)
        {
            if (Pcm == IntPtr.Zero)
                return;

            fixed (byte* Base = Samples)
            {
                int Offset = 0;
                while (Offset < Samples.Length)
                {
                    nuint Frames = (nuint)((Samples.Length - Offset) / BlockAlign);
                    if (Frames == 0)
                        return;

                    nint Written = snd_pcm_writei(Pcm, Base + Offset, Frames);
                    if (Written < 0)
                    {
                        if (snd_pcm_recover(Pcm, (int)Written, 1) < 0)
                            return;

                        continue;
                    }

                    Offset += (int)Written * BlockAlign;
                }
            }
        }

        public void Dispose()
        {
            if (Pcm == IntPtr.Zero)
                return;

            snd_pcm_close(Pcm);
            Pcm = IntPtr.Zero;
        }
    }
}
