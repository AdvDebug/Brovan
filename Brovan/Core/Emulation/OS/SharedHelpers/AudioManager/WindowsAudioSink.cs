using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    [SupportedOSPlatform("windows")]
    internal sealed unsafe class WindowsAudioSink : IAudioSink
    {
        private const uint WaveMapper = 0xFFFFFFFF;
        private const uint WaveFormatExtensible = 0xFFFE;
        private const uint WhdrDone = 0x00000001;
        private const uint CallbackEvent = 0x00050000;
        private const uint MmsysErrNoError = 0;

        private const int BufferCount = 4;
        private const int BufferMilliseconds = 20;

        [StructLayout(LayoutKind.Sequential)]
        private struct WaveHdr
        {
            public IntPtr Data;
            public uint BufferLength;
            public uint BytesRecorded;
            public IntPtr User;
            public uint Flags;
            public uint Loops;
            public IntPtr Next;
            public IntPtr Reserved;
        }

        [DllImport("winmm.dll")]
        private static extern uint waveOutOpen(out IntPtr Device, uint DeviceId, byte[] Format, IntPtr Callback, IntPtr Instance, uint Flags);

        [DllImport("winmm.dll")]
        private static extern uint waveOutPrepareHeader(IntPtr Device, WaveHdr* Header, uint Size);

        [DllImport("winmm.dll")]
        private static extern uint waveOutUnprepareHeader(IntPtr Device, WaveHdr* Header, uint Size);

        [DllImport("winmm.dll")]
        private static extern uint waveOutWrite(IntPtr Device, WaveHdr* Header, uint Size);

        [DllImport("winmm.dll")]
        private static extern uint waveOutReset(IntPtr Device);

        [DllImport("winmm.dll")]
        private static extern uint waveOutClose(IntPtr Device);

        private readonly int ChunkBytes;
        private readonly int QueueMilliseconds = BufferMilliseconds * BufferCount;
        private readonly AutoResetEvent BufferDone = new AutoResetEvent(false);
        private IntPtr Device;
        private readonly IntPtr Headers;
        private readonly IntPtr[] Buffers = new IntPtr[BufferCount];
        private int NextBuffer;
        private bool Disposed;

        public WindowsAudioSink(AudioSinkFormat Format)
        {
            ChunkBytes = Format.BytesPerSecond * BufferMilliseconds / 1000 / Format.BlockAlign * Format.BlockAlign;

            uint Status = waveOutOpen(out Device, WaveMapper, BuildFormat(Format),
                BufferDone.SafeWaitHandle.DangerousGetHandle(), IntPtr.Zero, CallbackEvent);
            if (Status != MmsysErrNoError)
                throw new InvalidOperationException($"waveOutOpen failed with {Status}.");

            Headers = Marshal.AllocHGlobal(sizeof(WaveHdr) * BufferCount);
            new Span<byte>((void*)Headers, sizeof(WaveHdr) * BufferCount).Clear();

            for (int Index = 0; Index < BufferCount; Index++)
            {
                Buffers[Index] = Marshal.AllocHGlobal(ChunkBytes);

                WaveHdr* Header = (WaveHdr*)Headers + Index;
                Header->Data = Buffers[Index];
                Header->BufferLength = (uint)ChunkBytes;
                Header->Flags = WhdrDone;
            }
        }

        public int QueuedBytes
        {
            get
            {
                int Total = 0;

                for (int Index = 0; Index < BufferCount; Index++)
                {
                    WaveHdr* Header = (WaveHdr*)Headers + Index;
                    if ((Volatile.Read(ref Header->Flags) & WhdrDone) == 0)
                        Total += (int)Header->BufferLength;
                }

                return Total;
            }
        }

        public void WaitForProgress(int TimeoutMilliseconds)
        {
            if (!Disposed)
                BufferDone.WaitOne(TimeoutMilliseconds);
        }

        public void Write(ReadOnlySpan<byte> Samples)
        {
            int Offset = 0;
            while (Offset < Samples.Length && !Disposed)
            {
                WaveHdr* Header = (WaveHdr*)Headers + NextBuffer;

                // A device that stops completing buffers must not wedge the engine thread, which would
                // stall the guest's ring behind it; give up on the chunk instead.
                while ((Volatile.Read(ref Header->Flags) & WhdrDone) == 0 && !Disposed)
                {
                    if (!BufferDone.WaitOne(QueueMilliseconds * 2))
                        return;
                }

                if (Disposed)
                    return;

                if ((Header->Flags & ~WhdrDone) != 0)
                    waveOutUnprepareHeader(Device, Header, (uint)sizeof(WaveHdr));

                int Count = Math.Min(ChunkBytes, Samples.Length - Offset);
                Samples.Slice(Offset, Count).CopyTo(new Span<byte>((void*)Header->Data, Count));

                Header->BufferLength = (uint)Count;
                Header->Flags = 0;

                if (waveOutPrepareHeader(Device, Header, (uint)sizeof(WaveHdr)) != MmsysErrNoError
                    || waveOutWrite(Device, Header, (uint)sizeof(WaveHdr)) != MmsysErrNoError)
                {
                    Header->Flags = WhdrDone;
                    return;
                }

                NextBuffer = (NextBuffer + 1) % BufferCount;
                Offset += Count;
            }
        }

        /// <summary>
        /// waveOut wants a WAVEFORMATEXTENSIBLE to accept float samples. a bare tag-3 WAVEFORMATEX is
        /// rejected by several drivers.
        /// </summary>
        private static byte[] BuildFormat(AudioSinkFormat Format)
        {
            byte[] Bytes = new byte[40];
            Span<byte> Cursor = Bytes;

            BitConverter.TryWriteBytes(Cursor.Slice(0x00, 2), (ushort)WaveFormatExtensible);
            BitConverter.TryWriteBytes(Cursor.Slice(0x02, 2), Format.Channels);
            BitConverter.TryWriteBytes(Cursor.Slice(0x04, 4), Format.SampleRate);
            BitConverter.TryWriteBytes(Cursor.Slice(0x08, 4), (uint)Format.BytesPerSecond);
            BitConverter.TryWriteBytes(Cursor.Slice(0x0C, 2), (ushort)Format.BlockAlign);
            BitConverter.TryWriteBytes(Cursor.Slice(0x0E, 2), Format.BitsPerSample);
            BitConverter.TryWriteBytes(Cursor.Slice(0x10, 2), (ushort)22);
            BitConverter.TryWriteBytes(Cursor.Slice(0x12, 2), Format.BitsPerSample);
            BitConverter.TryWriteBytes(Cursor.Slice(0x14, 4), Format.Channels == 1 ? 0x4u : 0x3u);
            KsDataFormatSubtypeIeeeFloat.CopyTo(Cursor.Slice(0x18, 16));

            return Bytes;
        }

        private static readonly byte[] KsDataFormatSubtypeIeeeFloat =
        {
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
        };

        public void Dispose()
        {
            if (Disposed)
                return;

            Disposed = true;
            BufferDone.Set();

            if (Device != IntPtr.Zero)
            {
                waveOutReset(Device);

                for (int Index = 0; Index < BufferCount; Index++)
                    waveOutUnprepareHeader(Device, (WaveHdr*)Headers + Index, (uint)sizeof(WaveHdr));

                waveOutClose(Device);
                Device = IntPtr.Zero;
            }

            for (int Index = 0; Index < BufferCount; Index++)
            {
                if (Buffers[Index] != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(Buffers[Index]);
                    Buffers[Index] = IntPtr.Zero;
                }
            }

            if (Headers != IntPtr.Zero)
                Marshal.FreeHGlobal(Headers);

            BufferDone.Dispose();
        }
    }
}
