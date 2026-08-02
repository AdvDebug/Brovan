using System;
using System.Threading;

namespace Brovan.Android
{
    internal static class AndroidHost
    {
        private const int SurfaceWaitMilliseconds = 30000;

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
