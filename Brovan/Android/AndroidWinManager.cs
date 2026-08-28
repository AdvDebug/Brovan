using System;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal sealed class AndroidWinManager : IDisplayConnection, IGdiRenderSupport, ITextRenderSupport, ITextMetricsSupport
    {
        private const int EFD_CLOEXEC = 0x80000;
        private const int EFD_NONBLOCK = 0x800;

        private const uint WM_SIZE = 0x0005;
        private const uint SIZE_RESTORED = 0;

        private static AndroidWinManager _current;

        private readonly AndroidGdiSurface _gdi = new();

        private int _wakeFd = -1;
        private int _publishedWidth;
        private int _publishedHeight;

        private AndroidWindow _window;
        private volatile bool _disposed;

        public AndroidWinManager()
        {
            if (!AndroidHost.IsActive)
                throw new PlatformNotSupportedException("The Android window backend requires brovan_init to have run first.");

            _wakeFd = Posix.EventFd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            HostEventQueue.RawMouseAvailable = true;
            _current = this;
        }

        public static AndroidWinManager Current => _current;

        public bool IsConnected => !_disposed && AndroidHost.NativeWindow != IntPtr.Zero;

        public IntPtr NativeHandle => AndroidHost.NativeWindow;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(AndroidWinManager));

            options ??= new WindowOptions();

            // The guest asks for its window as soon as it starts, but the Surface only exists once the app's
            // SurfaceView has been laid out. Handing back a window with no ANativeWindow would let the guest
            // build a Vulkan surface on a null handle, so block until the app attaches one.
            if (!AndroidHost.WaitForSurface())
                throw new PlatformNotSupportedException("No Android surface was attached; the host app must call brovan_set_surface before running a guest that draws.");

            AndroidHost.WindowTitle = options.Title ?? string.Empty;
            _window = new AndroidWindow(options);

            // Host events delivered before the guest had a window drained into nothing. The surface size in
            // particular is published only on change, so without this the guest never hears it and a guest
            // that waits for its first size event never starts presenting.
            _publishedWidth = 0;
            _publishedHeight = 0;
            AndroidInput.ReplayFocus();
            return _window;
        }

        public void PumpEvents()
        {
            if (_disposed)
                return;

            PublishSurfaceSize();
            _gdi.Flush();
        }

        // The Surface carries no resize stream of its own, so the guest window would keep the size the guest
        // asked for while the Vulkan surface reports the Surface.
        private void PublishSurfaceSize()
        {
            int width = AndroidHost.Width;
            int height = AndroidHost.Height;

            if (width <= 0 || height <= 0 || (width == _publishedWidth && height == _publishedHeight))
                return;

            _publishedWidth = width;
            _publishedHeight = height;

            HostEventQueue.Enqueue(WM_SIZE, SIZE_RESTORED, MakeLParam(width, height));
            HostEventQueue.MarkRepaint();
        }

        private static ulong MakeLParam(int low, int high)
        {
            return (ulong)(uint)(((high & 0xFFFF) << 16) | (low & 0xFFFF));
        }

        public void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive)
        {
            if (!_disposed)
                _gdi.Execute(primitive);
        }

        public void RenderText(IntPtr windowHandle, ulong hwnd, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (!_disposed)
                _gdi.DrawText(hwnd, text, x, y, rectLeft, rectTop, rectRight, rectBottom, options);
        }

        public bool MeasureText(string text, out int width, out int height)
        {
            return AndroidText.Measure(text, out width, out height);
        }

        public bool GetTextMetrics(out TextMetricsData metrics)
        {
            return AndroidText.GetMetrics(out metrics);
        }

        public void InvalidateSurface()
        {
            if (!_disposed)
                _gdi.Invalidate();
        }

        public unsafe void WaitForEvents(int timeoutMilliseconds)
        {
            int wakeFd = Volatile.Read(ref _wakeFd);
            if (wakeFd < 0)
                return;

            Posix.PollFd descriptor;
            descriptor.Fd = wakeFd;
            descriptor.Events = Posix.POLLIN;
            descriptor.RevEvents = 0;

            if (Posix.Poll(&descriptor, 1, timeoutMilliseconds) <= 0)
                return;

            if ((descriptor.RevEvents & Posix.POLLIN) != 0)
            {
                ulong drained;
                Posix.Read(wakeFd, &drained, sizeof(ulong));
            }
        }

        public unsafe void Wake()
        {
            int wakeFd = Volatile.Read(ref _wakeFd);
            if (wakeFd < 0)
                return;

            ulong token = 1;
            Posix.Write(wakeFd, &token, sizeof(ulong));
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _window?.Dispose();
            _window = null;

            if (ReferenceEquals(_current, this))
                _current = null;
        }

        private sealed class AndroidWindow : IWindow
        {
            private readonly bool _resizable;

            private bool _disposed;
            private string _title;
            private bool _visible;
            private bool _decorated;
            private WindowState _state;

            internal AndroidWindow(WindowOptions options)
            {
                _title = options.Title ?? string.Empty;
                _visible = options.Visible;
                _decorated = options.Decorated;
                _resizable = options.Resizable;
                _state = options.State;
            }

            public string Title
            {
                get => _title;
                set
                {
                    EnsureAlive();
                    _title = value ?? string.Empty;
                    AndroidHost.WindowTitle = _title;
                }
            }

            // The Surface is sized by the app and the compositor, so the guest can read the real dimensions
            // but cannot drive them; a resize request is accepted and ignored rather than failed, because
            // guests routinely size their window and carry on regardless of the result.
            public int Width
            {
                get => AndroidHost.Width;
                set { }
            }

            public int Height
            {
                get => AndroidHost.Height;
                set { }
            }

            public bool Visible
            {
                get => _visible;
                set
                {
                    EnsureAlive();
                    _visible = value;
                }
            }

            public WindowState State
            {
                get => _state;
                set
                {
                    EnsureAlive();
                    _state = value;
                }
            }

            public bool Resizable => _resizable;

            public bool Decorated
            {
                get => _decorated;
                set
                {
                    EnsureAlive();
                    _decorated = value;
                }
            }

            public IntPtr NativeHandle => AndroidHost.NativeWindow;

            // Nothing to apply: the host window is the app's Surface, which the app owns.
            public void Present()
            {
            }

            // Touch input has no pointer to move; the guest's own cursor position is authoritative here.
            public void WarpCursor(int clientX, int clientY)
            {
            }

            public void SetCursorVisible(bool visible)
            {
            }

            public void Show() => Visible = true;

            public void Hide() => Visible = false;

            public void Close() => Dispose();

            public void Dispose()
            {
                _disposed = true;
            }

            private void EnsureAlive()
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(AndroidWindow));
            }
        }
    }
}
