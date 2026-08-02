using System;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Android
{
    internal sealed class AndroidWinManager : IDisplayConnection, IGdiRenderSupport
    {
        private const int EFD_CLOEXEC = 0x80000;
        private const int EFD_NONBLOCK = 0x800;

        private static AndroidWinManager _current;

        private readonly AndroidGdiSurface _gdi = new();

        private int _wakeFd = -1;

        private AndroidWindow _window;
        private volatile bool _disposed;

        public AndroidWinManager()
        {
            if (!AndroidHost.IsActive)
                throw new PlatformNotSupportedException("The Android window backend requires brovan_init to have run first.");

            _wakeFd = Posix.EventFd(0, EFD_CLOEXEC | EFD_NONBLOCK);
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
            return _window;
        }

        public void PumpEvents()
        {
            if (!_disposed)
                _gdi.Flush();
        }

        public void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive)
        {
            if (!_disposed)
                _gdi.Execute(primitive);
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
