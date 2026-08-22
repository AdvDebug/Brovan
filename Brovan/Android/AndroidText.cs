using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal struct AndroidTextBitmap
    {
        public byte[] Coverage;
        public int Width;
        public int Height;
        public int Ascent;
        public int Padding;
    }

    internal static unsafe class AndroidText
    {
        private const int InitialCoverage = 64 * 1024;
        private const int MaximumCoverage = 32 * 1024 * 1024;
        private const byte SansSerifTrueType = 0x27;

        [StructLayout(LayoutKind.Sequential)]
        private struct TextRequest
        {
            public byte* Coverage;
            public int Capacity;
            public int Width;
            public int Height;
            public int Ascent;
            public int Descent;
            public int Leading;
            public int AverageWidth;
            public int MaximumWidth;
            public int Padding;
        }

        private static readonly object Sync = new();

        private static IntPtr _sink;
        private static byte[] _coverage = Array.Empty<byte>();

        public static void SetSink(IntPtr sink)
        {
            Volatile.Write(ref _sink, sink);
        }

        public static bool Measure(string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            TextRequest request = default;
            if (!Invoke(text ?? string.Empty, ref request))
                return false;

            width = Math.Max(request.Width - (request.Padding * 2), 0);
            height = request.Ascent + request.Descent;
            return true;
        }

        public static bool GetMetrics(out TextMetricsData metrics)
        {
            metrics = default;

            TextRequest request = default;
            if (!Invoke(null, ref request))
                return false;

            metrics.Height = request.Ascent + request.Descent;
            metrics.Ascent = request.Ascent;
            metrics.Descent = request.Descent;
            metrics.ExternalLeading = request.Leading;
            metrics.AveCharWidth = Math.Max(request.AverageWidth, 1);
            metrics.MaxCharWidth = Math.Max(request.MaximumWidth, request.AverageWidth);
            metrics.Weight = 400;
            metrics.DigitizedAspectX = (int)HostDisplayMetrics.SystemDpi;
            metrics.DigitizedAspectY = (int)HostDisplayMetrics.SystemDpi;
            metrics.FirstChar = 0x20;
            metrics.LastChar = 0xFFFF;
            metrics.DefaultChar = 0x3F;
            metrics.BreakChar = 0x20;
            metrics.PitchAndFamily = SansSerifTrueType;
            return true;
        }

        /// <summary>
        /// Draws the run into an 8 bit coverage bitmap.
        /// </summary>
        public static bool Rasterize(string text, out AndroidTextBitmap bitmap)
        {
            bitmap = default;

            if (string.IsNullOrEmpty(text))
                return false;

            lock (Sync)
            {
                // A null buffer is how the host tells a measurement from a draw, so the first draw needs one.
                if (_coverage.Length == 0)
                    _coverage = new byte[InitialCoverage];

                for (int attempt = 0; attempt < 2; attempt++)
                {
                    TextRequest request = default;
                    bool rasterized;

                    fixed (byte* buffer = _coverage)
                    {
                        request.Coverage = buffer;
                        request.Capacity = _coverage.Length;
                        rasterized = Invoke(text, ref request);
                    }

                    if (rasterized)
                    {
                        if (request.Width <= 0 || request.Height <= 0)
                            return false;

                        bitmap.Coverage = _coverage;
                        bitmap.Width = request.Width;
                        bitmap.Height = request.Height;
                        bitmap.Ascent = request.Ascent;
                        bitmap.Padding = request.Padding;
                        return true;
                    }

                    if (!Grow(request))
                        return false;
                }

                return false;
            }
        }

        private static bool Grow(in TextRequest request)
        {
            long needed = (long)request.Width * request.Height;
            if (needed <= _coverage.Length || needed > MaximumCoverage)
                return false;

            _coverage = new byte[needed];
            return true;
        }

        private static bool Invoke(string text, ref TextRequest request)
        {
            IntPtr sink = Volatile.Read(ref _sink);
            if (sink == IntPtr.Zero)
                return false;

            fixed (TextRequest* target = &request)
            {
                if (text == null)
                    return ((delegate* unmanaged<byte*, TextRequest*, int>)sink)(null, target) != 0;

                int capacity = Encoding.UTF8.GetMaxByteCount(text.Length) + 1;
                byte[] utf8 = ArrayPool<byte>.Shared.Rent(capacity);
                try
                {
                    int written = Encoding.UTF8.GetBytes(text, utf8);
                    utf8[written] = 0;

                    fixed (byte* encoded = utf8)
                        return ((delegate* unmanaged<byte*, TextRequest*, int>)sink)(encoded, target) != 0;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(utf8);
                }
            }
        }
    }
}
