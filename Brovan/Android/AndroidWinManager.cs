using System;
using System.Runtime.InteropServices;
using System.Threading;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Emulation.OS.Windows.Win32k;

namespace Brovan.Android
{
    internal sealed class AndroidWinManager : IDisplayConnection, IGdiRenderSupport, ITextRenderSupport, ITextMetricsSupport, ITopLevelWindowHost
    {
        private const int EFD_CLOEXEC = 0x80000;
        private const int EFD_NONBLOCK = 0x800;

        private const uint WM_MOVE = 0x0003;
        private const uint WM_SIZE = 0x0005;
        private const uint SIZE_RESTORED = 0;
        private const uint SIZE_MAXIMIZED = 2;
        private const int MaxFillRefusals = 3;

        private static AndroidWinManager _current;
        private static long _nextFont;

        private readonly AndroidGdiSurface _gdi = new();

        private int _wakeFd = -1;
        private int _publishedWidth;
        private int _publishedHeight;

        private AndroidWindow _window;
        private volatile bool _disposed;

        // GUI thread only.
        private readonly Dictionary<IntPtr, AndroidTopLevel> _topLevels = new();
        private bool _firstLayerShown;

        public AndroidWinManager()
        {
            if (!AndroidHost.IsActive)
                throw new PlatformNotSupportedException("The Android window backend requires brovan_init to have run first.");

            _wakeFd = Posix.EventFd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            HostEventQueue.RawMouseAvailable = true;
            AndroidHost.TopLevelMode = false;
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
            // build a Vulkan surface on a null handle, so block until the app has attached one at least once.
            if (!AndroidHost.WaitForSurface())
                throw new PlatformNotSupportedException("No Android surface was attached; the host app must call brovan_set_surface before running a guest that draws.");

            AndroidHost.WindowTitle = options.Title ?? string.Empty;
            _window = new AndroidWindow(options);

            // Replay the size and focus the guest missed before its window existed. The surface size is
            // published only on change, and a guest can wait for its first size event before it presents.
            _publishedWidth = 0;
            _publishedHeight = 0;
            AndroidInput.ReplayFocus();
            AndroidHost.NotifyPlayer(AndroidHost.PlayerWindowCreated);
            return _window;
        }

        public bool TopLevelsAvailable => AndroidHost.LayersAvailable;

        public bool SupportsLayered => true;

        public void UseTopLevels()
        {
            AndroidHost.TopLevelMode = true;
            _publishedWidth = AndroidHost.Width;
            _publishedHeight = AndroidHost.Height;
        }

        public bool TryCreateTopLevel(in TopLevelFrame frame, ITopLevelWindow owner, out ITopLevelWindow window)
        {
            window = null;
            if (_disposed)
                return false;

            IntPtr native = AndroidHost.CreateLayer(out int layer);
            if (native == IntPtr.Zero)
                return false;

            AndroidTopLevel created = new(this, layer, native, frame, owner as AndroidTopLevel);
            _topLevels[native] = created;

            if (!_firstLayerShown)
            {
                _firstLayerShown = true;
                AndroidInput.ReplayFocus();
                AndroidHost.NotifyPlayer(AndroidHost.PlayerWindowCreated);
            }

            created.Place();
            window = created;
            return true;
        }

        public void Restack(ReadOnlySpan<ITopLevelWindow> topToBottom)
        {
            for (int i = 0; i < topToBottom.Length; i++)
                ((AndroidTopLevel)topToBottom[i]).SetOrder(topToBottom.Length - i);
        }

        public void PumpEvents()
        {
            if (_disposed)
                return;

            if (AndroidHost.TopLevelMode)
            {
                PlaceForSurface();
                foreach (AndroidTopLevel topLevel in _topLevels.Values)
                    topLevel.Flush();

                return;
            }

            PublishSurfaceSize();
            _gdi.Flush();
        }

        private void PlaceForSurface()
        {
            if (!TryTakeSurfaceSize(out _, out _))
                return;

            foreach (AndroidTopLevel topLevel in _topLevels.Values)
                topLevel.Refill();
        }

        // The Surface carries no resize stream of its own, so the guest window would keep the size the guest
        // asked for while the Vulkan surface reports the Surface.
        private void PublishSurfaceSize()
        {
            if (!TryTakeSurfaceSize(out int width, out int height))
                return;

            HostEventQueue.Enqueue(WM_SIZE, SIZE_RESTORED, HostEventQueue.MakeLParam(width, height));
            HostEventQueue.MarkRepaint();
        }

        private bool TryTakeSurfaceSize(out int width, out int height)
        {
            width = AndroidHost.Width;
            height = AndroidHost.Height;
            if (width <= 0 || height <= 0 || (width == _publishedWidth && height == _publishedHeight))
                return false;

            _publishedWidth = width;
            _publishedHeight = height;
            return true;
        }

        public void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive)
        {
            if (_disposed)
                return;

            if (!AndroidHost.TopLevelMode)
                _gdi.Execute(primitive);
            else if (_topLevels.TryGetValue(windowHandle, out AndroidTopLevel topLevel))
                AndroidGdiSurface.Execute(topLevel.Buffer, primitive);
        }

        // Android draws with one system face, so a font handle selects nothing.
        public void RenderText(IntPtr windowHandle, ulong hwnd, IntPtr font, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options, GdiClipRect[] clip)
        {
            if (_disposed)
                return;

            if (!AndroidHost.TopLevelMode)
                _gdi.DrawText(hwnd, text, x, y, rectLeft, rectTop, rectRight, rectBottom, options, clip);
            else if (_topLevels.TryGetValue(windowHandle, out AndroidTopLevel topLevel))
                AndroidGdiSurface.DrawText(topLevel.Buffer, text, x, y, rectLeft, rectTop, rectRight, rectBottom, options, clip);
        }

        public bool MeasureText(IntPtr font, string text, out int width, out int height)
        {
            return AndroidText.Measure(text, out width, out height);
        }

        public bool GetTextMetrics(IntPtr font, out TextMetricsData metrics)
        {
            return AndroidText.GetMetrics(out metrics);
        }

        public bool RasterizeText(IntPtr font, string text, Span<uint> pixels, int width, int height,
            int x, int y, uint textColor, uint backColor, bool opaque, uint options)
        {
            int count = width * height;
            if (width <= 0 || height <= 0 || pixels.Length < count)
                return false;

            Span<uint> surface = pixels.Slice(0, count);
            if (opaque)
                surface.Fill(HostColor.FromColorRef(backColor));

            if (string.IsNullOrEmpty(text))
                return true;

            if (!AndroidText.Rasterize(text, out AndroidTextBitmap bitmap))
                return false;

            // The coverage bitmap is inset by its padding on each side, and y is the top of the cell.
            Blend(surface, bitmap, x - bitmap.Padding, y - bitmap.Padding, width, height, HostColor.FromColorRef(textColor));
            return true;
        }

        private static void Blend(Span<uint> surface, in AndroidTextBitmap bitmap, int left, int top, int width, int height, uint color)
        {
            int firstRow = Math.Max(0, -top);
            int lastRow = Math.Min(bitmap.Height, height - top);
            int firstColumn = Math.Max(0, -left);
            int lastColumn = Math.Min(bitmap.Width, width - left);

            uint red = (color >> 16) & 0xFF;
            uint green = (color >> 8) & 0xFF;
            uint blue = color & 0xFF;

            for (int row = firstRow; row < lastRow; row++)
            {
                int source = row * bitmap.Width;
                Span<uint> target = surface.Slice((top + row) * width, width);

                for (int column = firstColumn; column < lastColumn; column++)
                {
                    uint coverage = bitmap.Coverage[source + column];
                    if (coverage == 0)
                        continue;

                    if (coverage == 0xFF)
                    {
                        target[left + column] = color;
                        continue;
                    }

                    uint pixel = target[left + column];
                    uint remaining = 255 - coverage;

                    uint blended = ((((pixel >> 16) & 0xFF) * remaining + (red * coverage)) / 255) << 16;
                    blended |= ((((pixel >> 8) & 0xFF) * remaining + (green * coverage)) / 255) << 8;
                    blended |= ((pixel & 0xFF) * remaining + (blue * coverage)) / 255;

                    target[left + column] = blended;
                }
            }
        }

        public IntPtr CreateFont(in FontDescription description)
        {
            return (IntPtr)Interlocked.Increment(ref _nextFont);
        }

        public void DeleteFont(IntPtr font)
        {
        }

        // Android draws with one system face, so that is the whole enumeration.
        public IReadOnlyList<FontFamilyData> EnumerateFontFamilies(string faceName, byte charSet)
        {
            const string SystemFace = "Roboto";

            if (!string.IsNullOrEmpty(faceName) && !faceName.Equals(SystemFace, StringComparison.OrdinalIgnoreCase))
                return Array.Empty<FontFamilyData>();

            AndroidText.GetMetrics(out TextMetricsData metrics);

            return new FontFamilyData[]
            {
                new FontFamilyData
                {
                    FaceName = SystemFace,
                    FullName = SystemFace,
                    Style = "Regular",
                    CharSet = metrics.CharSet,
                    PitchAndFamily = metrics.PitchAndFamily,
                    Weight = metrics.Weight != 0 ? metrics.Weight : 400,
                    Metrics = metrics,
                }
            };
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

            foreach (AndroidTopLevel topLevel in new List<AndroidTopLevel>(_topLevels.Values))
                topLevel.Dispose();

            if (ReferenceEquals(_current, this))
            {
                AndroidHost.TopLevelMode = false;
                _current = null;
            }
        }

        private sealed class AndroidTopLevel : ITopLevelWindow
        {
            private readonly AndroidWinManager _manager;
            private readonly int _layer;
            private readonly ulong _guest;
            private IntPtr _native;

            private AndroidTopLevel _owner;
            private uint _style;
            private uint _exStyle;
            private string _title;
            private WindowState _state;
            private bool _shown;
            private int _order;

            private int _requestedX;
            private int _requestedY;
            private int _requestedWidth;
            private int _requestedHeight;
            private int _x;
            private int _y;
            private int _width;
            private int _height;
            private bool _fillReported;
            private int _fillRefusals;

            private bool _keyed;
            private int _key;
            private float _alpha = 1f;

            private AndroidGdiSurface.WindowBuffer _layered;
            private int _layeredX;
            private int _layeredY;
            private int _layeredWidth;
            private int _layeredHeight;

            private readonly record struct LayerState(int X, int Y, int Width, int Height, int Z, bool Shown, float Alpha);
            private LayerState? _applied;

            internal readonly AndroidGdiSurface.WindowBuffer Buffer = new();

            internal AndroidTopLevel(AndroidWinManager manager, int layer, IntPtr native, in TopLevelFrame frame, AndroidTopLevel owner)
            {
                _manager = manager;
                _layer = layer;
                _native = native;
                _guest = frame.Window;
                _owner = owner;
                _style = frame.Style;
                _exStyle = frame.ExStyle;
                _title = frame.Title ?? string.Empty;
                _state = WindowState.Normal;
                _requestedX = frame.ClientX;
                _requestedY = frame.ClientY;
                _requestedWidth = frame.ClientWidth;
                _requestedHeight = frame.ClientHeight;
            }

            // A phone has no window manager, so an unowned window with a caption fills the screen.
            private bool FillsScreen => _owner == null && Win32kHelper.HasCaption(_style);

            private bool FillAccepted => _fillRefusals <= MaxFillRefusals;

            internal void Place()
            {
                if (_layered != null)
                {
                    _x = _layeredX;
                    _y = _layeredY;
                    _width = _layeredWidth;
                    _height = _layeredHeight;
                    Apply();
                    return;
                }

                int surfaceWidth = AndroidHost.Width;
                int surfaceHeight = AndroidHost.Height;
                bool fills = FillsScreen && FillAccepted && surfaceWidth > 0 && surfaceHeight > 0;

                _x = fills ? 0 : _requestedX;
                _y = fills ? 0 : _requestedY;
                _width = Math.Max(fills ? surfaceWidth : _requestedWidth, 1);
                _height = Math.Max(fills ? surfaceHeight : _requestedHeight, 1);

                if (Buffer.Resize(_width, _height))
                    HostEventQueue.MarkRepaint(_guest);

                Apply();

                if (!fills)
                {
                    _fillReported = false;
                    return;
                }

                if (_fillReported || _requestedWidth <= 0 || _requestedHeight <= 0)
                    return;

                _fillReported = true;
                if (_requestedX != 0 || _requestedY != 0)
                    HostEventQueue.Enqueue(WM_MOVE, 0, 0, _guest);

                if (_requestedWidth != surfaceWidth || _requestedHeight != surfaceHeight)
                {
                    uint sizeType = _state == WindowState.Maximized ? SIZE_MAXIMIZED : SIZE_RESTORED;
                    HostEventQueue.Enqueue(WM_SIZE, sizeType, HostEventQueue.MakeLParam(surfaceWidth, surfaceHeight), _guest);
                }
            }

            internal void Refill()
            {
                _fillReported = false;
                _fillRefusals = 0;
                Place();
            }

            internal void SetOrder(int order)
            {
                if (order == _order)
                    return;

                _order = order;
                Apply();
            }

            private void Apply()
            {
                if (_native == IntPtr.Zero)
                    return;

                LayerState state = new(_x, _y, _width, _height, _order, _shown && _state != WindowState.Minimized, _alpha);
                if (state == _applied)
                    return;

                _applied = state;
                AndroidHost.ApplyLayer(_layer, state.X, state.Y, state.Width, state.Height, state.Z, state.Shown, state.Alpha);
            }

            internal void Flush()
            {
                if (!_shown || _native == IntPtr.Zero)
                    return;

                if (_layered != null)
                {
                    if (_layered.Dirty && _layered.Width != 0)
                        AndroidGdiSurface.Post(_native, _layered.Pixels, _layered.Width, _layered.Height, false, 0, true);

                    _layered.Dirty = false;
                    return;
                }

                if (Buffer.Dirty && Buffer.Width != 0)
                    AndroidGdiSurface.Post(_native, Buffer.Pixels, Buffer.Width, Buffer.Height, _keyed, _key, false);

                Buffer.Dirty = false;
            }

            public string Title
            {
                get => _title;
                set
                {
                    _title = value ?? string.Empty;
                    if (FillsScreen)
                        AndroidHost.WindowTitle = _title;
                }
            }

            public int Width
            {
                get => _width;
                set { }
            }

            public int Height
            {
                get => _height;
                set { }
            }

            public bool Visible
            {
                get => _shown;
                set => SetShown(value);
            }

            public WindowState State
            {
                get => _state;
                set
                {
                    _state = value;
                    if (_state == WindowState.Minimized)
                        Apply();
                    else
                        Refill();
                }
            }

            public bool Resizable => true;

            public bool Decorated
            {
                get => false;
                set { }
            }

            public IntPtr NativeHandle => _native;

            public void SetFrame(uint style, uint exStyle)
            {
                bool keptMaximized = FillsScreen;
                _style = style;
                _exStyle = exStyle;

                if ((exStyle & Win32kHelper.WindowExStyleLayered) == 0)
                    ForgetLayered();

                if (keptMaximized != FillsScreen)
                    Place();
                else
                    Apply();
            }

            public void SetOwner(ITopLevelWindow owner)
            {
                bool keptMaximized = FillsScreen;
                _owner = owner as AndroidTopLevel;
                if (keptMaximized != FillsScreen)
                    Place();
            }

            public void SetClientBounds(int x, int y, int width, int height)
            {
                if (_fillReported && (x != 0 || y != 0 || width != AndroidHost.Width || height != AndroidHost.Height))
                {
                    _fillRefusals++;
                    _fillReported = false;
                }

                _requestedX = x;
                _requestedY = y;
                _requestedWidth = width;
                _requestedHeight = height;
                Place();
            }

            // The guest drops input to a disabled window itself.
            public void SetEnabled(bool enabled)
            {
            }

            public void SetShown(bool shown)
            {
                if (shown == _shown)
                    return;

                _shown = shown;
                Apply();
            }

            // Restack orders the layers, and Android focus belongs to the whole player.
            public void Activate()
            {
            }

            public void SetLayeredAttributes(uint colorKey, byte alpha, uint flags)
            {
                if ((_exStyle & Win32kHelper.WindowExStyleLayered) == 0)
                    return;

                ForgetLayered();
                _keyed = (flags & LayeredPixels.ColorKey) != 0;
                _key = AndroidGdiSurface.ToPixel(colorKey);
                _alpha = (flags & LayeredPixels.Alpha) != 0 ? alpha / 255f : 1f;
                Buffer.Dirty = true;
                Apply();
            }

            public void UpdateLayered(LayeredUpdate update)
            {
                if ((_exStyle & Win32kHelper.WindowExStyleLayered) == 0 || update.Width <= 0 || update.Height <= 0)
                    return;

                _keyed = false;
                _layered ??= new AndroidGdiSurface.WindowBuffer();
                _layered.Resize(update.Width, update.Height, 0);
                LayeredPixels.Apply(update, MemoryMarshal.Cast<int, uint>(_layered.Pixels.AsSpan(0, _layered.Width * _layered.Height)));

                _alpha = (update.Flags & LayeredPixels.Alpha) != 0 ? update.ConstantAlpha / 255f : 1f;
                _layered.Dirty = true;
                _layeredWidth = update.Width;
                _layeredHeight = update.Height;
                _layeredX = update.X;
                _layeredY = update.Y;
                Place();
            }

            private void ForgetLayered()
            {
                _layered = null;
                _keyed = false;
                _alpha = 1f;
                Buffer.Dirty = true;
            }

            public void Present()
            {
            }

            // Touch input has no pointer to move or confine.
            public void WarpCursor(int clientX, int clientY)
            {
            }

            public void SetCursorClip(bool enabled, int clientLeft, int clientTop, int clientRight, int clientBottom)
            {
            }

            public void SetCursorVisible(bool visible)
            {
            }

            public void Show() => SetShown(true);

            public void Hide() => SetShown(false);

            public void Close() => Dispose();

            public void Dispose()
            {
                if (_native == IntPtr.Zero)
                    return;

                _manager._topLevels.Remove(_native);
                AndroidNative.NativeWindowRelease(_native);
                _native = IntPtr.Zero;
                AndroidHost.ReleaseLayer(_layer);
            }
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

            public void SetCursorClip(bool enabled, int clientLeft, int clientTop, int clientRight, int clientBottom)
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
