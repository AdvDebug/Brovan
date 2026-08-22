using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Brovan.Android
{
    internal static class AndroidHost
    {
        private const int SurfaceWaitMilliseconds = 30000;
        private const int MaximumCores = 64;

        private static readonly object SurfaceSync = new();
        private static readonly ManualResetEventSlim SurfaceReady = new(false);

        private static IntPtr _nativeWindow;
        private static int _width;
        private static int _height;
        private static int _densityDpi;
        private static volatile bool _active;
        private static volatile string _windowTitle = string.Empty;

        public static bool IsActive => _active;

        public static int Width => Volatile.Read(ref _width);

        public static int Height => Volatile.Read(ref _height);

        public static int DensityDpi => Volatile.Read(ref _densityDpi);

        public static string WindowTitle
        {
            get => _windowTitle;
            set => _windowTitle = value ?? string.Empty;
        }

        public static IntPtr NativeWindow
        {
            get
            {
                lock (SurfaceSync)
                    return _nativeWindow;
            }
        }

        public static void MarkActive()
        {
            _active = true;
        }

        public static void SetSurface(IntPtr window, int width, int height, int densityDpi)
        {
            IntPtr previous;

            lock (SurfaceSync)
            {
                previous = _nativeWindow;
                if (previous == window && window != IntPtr.Zero)
                {
                    StoreMetrics(window, width, height, densityDpi);
                    return;
                }

                if (window != IntPtr.Zero)
                    AndroidNative.NativeWindowAcquire(window);

                _nativeWindow = window;
                StoreMetrics(window, width, height, densityDpi);
            }

            if (previous != IntPtr.Zero)
                AndroidNative.NativeWindowRelease(previous);

            if (window != IntPtr.Zero)
                SurfaceReady.Set();
            else
                SurfaceReady.Reset();
        }

        public static bool WaitForSurface()
        {
            return SurfaceReady.Wait(SurfaceWaitMilliseconds);
        }

        /// <summary>Keeps the calling thread off the slowest CPU cluster for the rest of its life.</summary>
        public static unsafe void PinToPerformanceCores()
        {
            ulong mask = PerformanceCoreMask();
            if (mask == 0)
                return;

            _ = Environment.ProcessorCount;

            if (AndroidNative.SchedSetAffinity(0, sizeof(ulong), &mask) != 0)
                AndroidLog.Write(AndroidNative.LogWarn, $"[brovan] sched_setaffinity(0x{mask:X}) failed with errno {Marshal.GetLastPInvokeError()}.");
            else
                AndroidLog.Write(AndroidNative.LogInfo, $"[brovan] Guest pinned to CPU mask 0x{mask:X}.");
        }

        private static ulong PerformanceCoreMask()
        {
            ulong mask = TierMask("cpu_capacity");
            return mask != 0 ? mask : TierMask("cpufreq/cpuinfo_max_freq");
        }

        private static ulong TierMask(string attribute)
        {
            Span<long> ranks = stackalloc long[MaximumCores];
            long slowest = long.MaxValue;
            long fastest = 0;

            for (int cpu = 0; cpu < MaximumCores; cpu++)
            {
                long rank = ReadRank($"/sys/devices/system/cpu/cpu{cpu}/{attribute}");
                ranks[cpu] = rank;
                if (rank <= 0)
                    continue;

                if (rank < slowest)
                    slowest = rank;

                if (rank > fastest)
                    fastest = rank;
            }

            if (slowest >= fastest)
                return 0;

            ulong mask = 0;
            for (int cpu = 0; cpu < MaximumCores; cpu++)
            {
                if (ranks[cpu] > slowest)
                    mask |= 1UL << cpu;
            }

            return mask;
        }

        private static long ReadRank(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return 0;

                return long.TryParse(File.ReadAllText(path).AsSpan().Trim(), out long value) ? value : 0;
            }
            catch (IOException)
            {
                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                return 0;
            }
        }

        private static void StoreMetrics(IntPtr window, int width, int height, int densityDpi)
        {
            if (width <= 0 && window != IntPtr.Zero)
                width = AndroidNative.NativeWindowGetWidth(window);

            if (height <= 0 && window != IntPtr.Zero)
                height = AndroidNative.NativeWindowGetHeight(window);

            Volatile.Write(ref _width, width > 0 ? width : 0);
            Volatile.Write(ref _height, height > 0 ? height : 0);

            if (densityDpi > 0)
                Volatile.Write(ref _densityDpi, densityDpi);
        }
    }
}
