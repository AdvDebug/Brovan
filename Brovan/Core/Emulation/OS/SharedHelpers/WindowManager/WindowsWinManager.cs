using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal sealed class WindowsWinManager : IDisplayConnection, ITextRenderSupport, ITextMetricsSupport, IGdiRenderSupport, IKeyboardTranslateSupport, ITopLevelWindowHost
    {
        private static readonly ConcurrentDictionary<IntPtr, WindowsWindow> Windows = new();

        private static readonly WindowProcDelegate WindowProcHandler = WindowProc;
        private static readonly IntPtr WindowProcPointer = Marshal.GetFunctionPointerForDelegate(WindowProcHandler);

        private static readonly object MetricsLock = new();
        private static IntPtr _metricsDc = IntPtr.Zero;
        private static DibSurface _raster;
        private static IntPtr _metricsFont = IntPtr.Zero;
        private static IntPtr _metricsPreviousFont = IntPtr.Zero;

        private static readonly Dictionary<(int Width, int ColorRef), IntPtr> _penCache = new();
        private static readonly Dictionary<int, IntPtr> _brushCache = new();

        private static IntPtr _stockBlackPen;
        private static IntPtr _stockWhiteBrush;

        private static IntPtr StockBlackPen
        {
            get
            {
                if (_stockBlackPen == IntPtr.Zero)
                    _stockBlackPen = GetStockObject(STOCK_OBJECT_BLACK_PEN);

                return _stockBlackPen;
            }
        }

        private static IntPtr StockWhiteBrush
        {
            get
            {
                if (_stockWhiteBrush == IntPtr.Zero)
                    _stockWhiteBrush = GetStockObject(STOCK_OBJECT_WHITE_BRUSH);

                return _stockWhiteBrush;
            }
        }

        private static IntPtr GetOrCreatePen(int width, int colorRef)
        {
            width = Math.Max(width, 1);
            (int, int) key = (width, colorRef);
            if (_penCache.TryGetValue(key, out IntPtr pen))
                return pen;

            pen = CreatePen(PS_SOLID, width, colorRef);
            if (pen != IntPtr.Zero)
                _penCache[key] = pen;

            return pen;
        }

        private static IntPtr GetOrCreateBrush(int colorRef)
        {
            if (_brushCache.TryGetValue(colorRef, out IntPtr brush))
                return brush;

            brush = CreateSolidBrush(colorRef);
            if (brush != IntPtr.Zero)
                _brushCache[colorRef] = brush;

            return brush;
        }

        private static void DisposeCachedPensAndBrushes()
        {
            foreach (IntPtr pen in _penCache.Values)
                DeleteObject(pen);
            _penCache.Clear();

            foreach (IntPtr brush in _brushCache.Values)
                DeleteObject(brush);
            _brushCache.Clear();
        }

        private readonly IntPtr _instanceHandle;
        private readonly string _className;

        /// <summary>
        /// Never disposed: a guest thread can submit work while the GUI thread is tearing the display down, and
        /// the SafeHandle behind this is what keeps that racing <see cref="Wake"/> off a recycled handle value.
        /// </summary>
        private readonly AutoResetEvent _wakeEvent = new(false);

        private bool _disposed;
        private bool _rawMouseFollowsFocus;

        // GUI thread only. Non-zero while the host applies a guest request, so its events are not echoed back.
        private int _applyingGuestState;

        // GUI thread only. Set when host activation leaves Brovan, so the next activation is not an echo.
        private bool _hostFocusLost;

        private readonly ref struct GuestApplyScope
        {
            private readonly WindowsWinManager _manager;

            public GuestApplyScope(WindowsWinManager manager)
            {
                _manager = manager;
                manager._applyingGuestState++;
            }

            public void Dispose() => _manager._applyingGuestState--;
        }

        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;
        private const int GWLP_HWNDPARENT = -8;

        private const uint WM_DESTROY = 0x0002;
        private const uint WM_CLOSE = 0x0010;
        private const uint WM_ERASEBKGND = 0x0014;
        private const uint WM_SIZE = 0x0005;
        private const uint WM_MOVE = 0x0003;
        private const uint SIZE_MINIMIZED = 1;
        private const uint SIZE_MAXIMIZED = 2;
        private const uint SIZE_MAXSHOW = 3;
        private const uint SIZE_MAXHIDE = 4;
        private const uint WM_PAINT = 0x000F;
        private const uint WM_SHOWWINDOW = 0x0018;
        private const uint WM_SETTEXT = 0x000C;
        private const uint WM_GETTEXT = 0x000D;
        private const uint WM_GETTEXTLENGTH = 0x000E;

        private const uint WM_KEYDOWN = 0x0100;
        private const uint WM_KEYUP = 0x0101;
        private const uint WM_CHAR = 0x0102;
        private const uint WM_SYSKEYDOWN = 0x0104;
        private const uint WM_SYSKEYUP = 0x0105;
        private const uint WM_MOUSEMOVE = 0x0200;
        private const uint WM_SETCURSOR = 0x0020;
        private const uint WM_INPUT = 0x00FF;
        private const uint WM_SETFOCUS = 0x0007;
        private const uint WM_KILLFOCUS = 0x0008;
        private const uint WM_ACTIVATE = 0x0006;
        private const uint WA_INACTIVE = 0;
        private const uint RID_INPUT = 0x10000003;
        private const uint RIM_TYPEMOUSE = 0;
        private const ushort MOUSE_MOVE_ABSOLUTE = 0x0001;
        private const ushort HidUsagePageGeneric = 0x01;
        private const ushort HidUsageMouse = 0x02;
        private const int HTCLIENT = 1;
        private static readonly IntPtr IDC_ARROW = new(32512);
        private const uint WM_LBUTTONDOWN = 0x0201;
        private const uint WM_LBUTTONUP = 0x0202;
        private const uint WM_RBUTTONDOWN = 0x0204;
        private const uint WM_RBUTTONUP = 0x0205;
        private const uint WM_MBUTTONDOWN = 0x0207;
        private const uint WM_MBUTTONUP = 0x0208;
        private const uint WM_MOUSEWHEEL = 0x020A;
        private const uint WM_XBUTTONDOWN = 0x020B;
        private const uint WM_XBUTTONUP = 0x020C;
        private const uint WM_MOUSEHWHEEL = 0x020E;

        private const uint WS_OVERLAPPEDWINDOW = 0x00CF0000;
        private const uint WS_POPUP = 0x80000000;
        private const uint WS_VISIBLE = 0x10000000;
        private const uint WS_CAPTION = 0x00C00000;
        private const uint WS_THICKFRAME = 0x00040000;
        private const uint WS_MINIMIZEBOX = 0x00020000;
        private const uint WS_MAXIMIZEBOX = 0x00010000;
        private const uint WS_SYSMENU = 0x00080000;
        private const uint WS_MINIMIZE = 0x20000000;
        private const uint WS_MAXIMIZE = 0x01000000;
        private const uint WS_DISABLED = 0x08000000;
        private const uint WS_CLIPSIBLINGS = 0x04000000;

        private const uint WS_EX_DLGMODALFRAME = 0x00000001;
        private const uint WS_EX_TOPMOST = 0x00000008;
        private const uint WS_EX_TRANSPARENT = 0x00000020;
        private const uint WS_EX_TOOLWINDOW = 0x00000080;
        private const uint WS_EX_WINDOWEDGE = 0x00000100;
        private const uint WS_EX_CLIENTEDGE = 0x00000200;
        private const uint WS_EX_STATICEDGE = 0x00020000;
        private const uint WS_EX_APPWINDOW = 0x00040000;
        private const uint WS_EX_LAYERED = 0x00080000;
        private const uint WS_EX_NOACTIVATE = 0x08000000;

        private const uint GuestFrameStyles = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
        private const uint GuestFrameExStyles = WS_EX_DLGMODALFRAME | WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW
            | WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_APPWINDOW | WS_EX_LAYERED | WS_EX_NOACTIVATE;
        private const uint HostWindowState = WS_VISIBLE | WS_MINIMIZE | WS_MAXIMIZE | WS_DISABLED;

        private const int SW_HIDE = 0;
        private const int SW_SHOWNORMAL = 1;
        private const int SW_SHOWNOACTIVATE = 4;
        private const int SW_SHOW = 5;
        private const int SW_MINIMIZE = 6;
        private const int SW_SHOWMINNOACTIVE = 7;
        private const int SW_SHOWNA = 8;
        private const int SW_MAXIMIZE = 3;
        private const int SW_RESTORE = 9;

        private static readonly IntPtr HWND_TOPMOST = new(-1);
        private static readonly IntPtr HWND_NOTOPMOST = new(-2);

        private const uint ULW_COLORKEY = 0x00000001;
        private const uint ULW_ALPHA = 0x00000002;
        private const uint ULW_OPAQUE = 0x00000004;
        private const byte AC_SRC_OVER = 0x00;

        private const uint PM_REMOVE = 0x0001;

        private const int StackPointLimit = 128;
        private const int StackClipLimit = 256;

        private const uint QS_ALLINPUT = 0x04FF;
        private const uint MWMO_INPUTAVAILABLE = 0x0004;
        private const uint INFINITE = 0xFFFFFFFF;

        private const uint CS_OWNDC = 0x0020;

        private const uint SWP_NOSIZE = 0x0001;
        private const uint SWP_NOMOVE = 0x0002;
        private const uint SWP_NOZORDER = 0x0004;
        private const uint SWP_NOACTIVATE = 0x0010;
        private const uint SWP_FRAMECHANGED = 0x0020;
        private const uint SWP_NOOWNERZORDER = 0x0200;

        private const uint WM_DPICHANGED = 0x02E0;

        private static readonly IntPtr DpiContextUnaware = new(-1);
        private static readonly IntPtr DpiContextSystemAware = new(-2);
        private static readonly IntPtr DpiContextPerMonitorAwareV2 = new(-4);

        private DpiAwareness _dpiAwareness = DpiAwareness.Unaware;
        private bool _dpiAwarenessApplied;

        public WindowsWinManager()
        {
            if (!GeneralHelper.IsWindows)
                throw new PlatformNotSupportedException("Windows window manager needs to be used on a Windows system.");

            _instanceHandle = GetModuleHandleW(null);
            _className = $"BrovanWindow_{Guid.NewGuid():N}";
            RegisterWindowClass();
        }

        public bool IsConnected => !_disposed;

        public IntPtr NativeHandle => IntPtr.Zero;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(WindowsWinManager));

            options = Normalize(options ?? new WindowOptions());
            ApplyDpiAwareness(options.DpiAwareness);

            uint style = options.Decorated ? WS_OVERLAPPEDWINDOW : WS_POPUP;
            if (options.Visible)
                style |= WS_VISIBLE;

            if (!options.Resizable)
                style &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX);

            int requestedClientWidth = Math.Max(options.Width, 1);
            int requestedClientHeight = Math.Max(options.Height, 1);
            ResolveOuterFromClient(style, 0, requestedClientWidth, requestedClientHeight, FrameDpi(IntPtr.Zero), out int outerWidth, out int outerHeight);

            IntPtr hwnd = CreateWindowExW(
                0,
                _className,
                string.IsNullOrWhiteSpace(options.Title) ? string.Empty : options.Title,
                style,
                options.X,
                options.Y,
                outerWidth,
                outerHeight,
                IntPtr.Zero,
                IntPtr.Zero,
                _instanceHandle,
                IntPtr.Zero);

            if (hwnd == IntPtr.Zero)
                throw new InvalidOperationException("CreateWindowExW failed.");

            WindowsWindow window = new(this, hwnd, options);
            Windows[hwnd] = window;

            ApplyBrovanAccent(hwnd);
            RegisterRawMouse(hwnd);
            ApplyInitialState(window, options);
            return window;
        }

        public ITopLevelWindow CreateTopLevel(in TopLevelFrame frame, ITopLevelWindow owner)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(WindowsWinManager));

            ApplyDpiAwareness(frame.DpiAwareness);

            uint style = HostStyle(frame.Style);
            uint exStyle = HostExStyle(frame.ExStyle);
            RECT outer = ClientToOuter(style, exStyle, frame.ClientX, frame.ClientY, frame.ClientWidth, frame.ClientHeight, FrameDpi(IntPtr.Zero));

            IntPtr hwnd = CreateWindowExW(
                unchecked((int)exStyle),
                _className,
                WindowsWindow.FormatTitle(frame.Title),
                style,
                outer.Left,
                outer.Top,
                outer.Right - outer.Left,
                outer.Bottom - outer.Top,
                owner?.NativeHandle ?? IntPtr.Zero,
                IntPtr.Zero,
                _instanceHandle,
                IntPtr.Zero);

            if (hwnd == IntPtr.Zero)
                throw new InvalidOperationException("CreateWindowExW failed.");

            WindowsWindow window = new(this, hwnd, frame, style, exStyle);
            Windows[hwnd] = window;

            ApplyBrovanAccent(hwnd);

            // A null target makes raw input follow the keyboard focus.
            if (!_rawMouseFollowsFocus)
            {
                RegisterRawMouse(IntPtr.Zero);
                _rawMouseFollowsFocus = true;
            }

            if (!frame.Enabled)
                EnableWindow(hwnd, false);

            window.SetClientBounds(frame.ClientX, frame.ClientY, frame.ClientWidth, frame.ClientHeight);
            return window;
        }

        // A window inserted behind a topmost window becomes topmost, so each band is restacked on its own.
        public void Restack(ReadOnlySpan<ITopLevelWindow> topToBottom)
        {
            using (new GuestApplyScope(this))
            {
                bool aboveTopmost = topToBottom.Length != 0 && IsTopmostHostWindow(topToBottom[0].NativeHandle);
                for (int i = 1; i < topToBottom.Length; i++)
                {
                    IntPtr window = topToBottom[i].NativeHandle;
                    bool topmost = IsTopmostHostWindow(window);
                    if (topmost == aboveTopmost)
                        SetWindowPos(window, topToBottom[i - 1].NativeHandle, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);

                    aboveTopmost = topmost;
                }
            }
        }

        private static bool IsTopmostHostWindow(IntPtr hwnd)
        {
            return (unchecked((uint)GetWindowLongPtrW(hwnd, GWL_EXSTYLE).ToInt64()) & WS_EX_TOPMOST) != 0;
        }

        private static uint HostStyle(uint guestStyle) => (guestStyle & GuestFrameStyles) | WS_CLIPSIBLINGS;

        private static uint HostExStyle(uint guestExStyle) => guestExStyle & GuestFrameExStyles;

        private static RECT ClientToOuter(uint style, uint exStyle, int x, int y, int width, int height, uint dpi)
        {
            RECT rect = new RECT { Left = x, Top = y, Right = x + Math.Max(width, 0), Bottom = y + Math.Max(height, 0) };
            AdjustFrameRect(ref rect, style, exStyle, dpi);
            return rect;
        }

        private bool IsHostWindow(IntPtr hwnd) => hwnd != IntPtr.Zero && Windows.ContainsKey(hwnd);

        public void PumpEvents()
        {
            if (_disposed)
                return;

            while (PeekMessageW(out MSG msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                if (msg.message == 0x0012)
                {
                    _disposed = true;
                    break;
                }

                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }
        }

        public void WaitForEvents(int timeoutMilliseconds)
        {
            if (_disposed)
            {
                _wakeEvent.WaitOne(timeoutMilliseconds < 0 ? Timeout.Infinite : timeoutMilliseconds);
                return;
            }

            IntPtr wakeHandle = _wakeEvent.SafeWaitHandle.DangerousGetHandle();
            uint timeout = timeoutMilliseconds < 0 ? INFINITE : (uint)timeoutMilliseconds;
            MsgWaitForMultipleObjectsEx(1, ref wakeHandle, timeout, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        }

        public void Wake()
        {
            _wakeEvent.Set();
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            foreach (KeyValuePair<IntPtr, WindowsWindow> entry in Windows)
            {
                if (Windows.TryRemove(entry.Key, out WindowsWindow window))
                    window.Dispose();
            }

            DisposeCachedPensAndBrushes();
        }

        private void RegisterWindowClass()
        {
            WNDCLASSEXW wndClass = new()
            {
                cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),

                style = CS_OWNDC,
                lpfnWndProc = WindowProcPointer,
                cbClsExtra = 0,
                cbWndExtra = 0,
                hInstance = _instanceHandle,
                hIcon = IntPtr.Zero,
                hCursor = IntPtr.Zero,
                hbrBackground = (IntPtr)6,
                lpszMenuName = null,
                lpszClassName = _className,
                hIconSm = IntPtr.Zero,
            };

            if (RegisterClassExW(ref wndClass) == 0)
                throw new InvalidOperationException("RegisterClassExW failed.");
        }

        private static WindowOptions Normalize(WindowOptions options)
        {
            options ??= new WindowOptions();
            if (options.Width <= 0)
                options = options with { Width = 800 };

            if (options.Height <= 0)
                options = options with { Height = 600 };

            return options;
        }

        private const int DWMWA_BORDER_COLOR = 34;
        private const uint BrovanAccentColor = 0x00FFA050;

        private static void ApplyBrovanAccent(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero)
                return;

            uint color = BrovanAccentColor;
            DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref color, sizeof(uint));
        }

        /// <summary>
        /// Asks the host for mouse travel straight off the device, so a guest in relative mode gets motion that a
        /// pointer position cannot carry: motion past the edge of the screen, and motion a warp did not cause.
        /// </summary>
        private static void RegisterRawMouse(IntPtr hwnd)
        {
            RAWINPUTDEVICE device = new()
            {
                usUsagePage = HidUsagePageGeneric,
                usUsage = HidUsageMouse,
                dwFlags = 0,
                hwndTarget = hwnd,
            };

            if (RegisterRawInputDevices(ref device, 1, (uint)Marshal.SizeOf<RAWINPUTDEVICE>()))
                HostEventQueue.RawMouseAvailable = true;
        }

        private static unsafe void ForwardRawInput(IntPtr rawInput)
        {
            int headerSize = 8 + 2 * IntPtr.Size;
            byte* buffer = stackalloc byte[128];
            uint size = 128;

            if (GetRawInputData(rawInput, RID_INPUT, (IntPtr)buffer, ref size, (uint)headerSize) == uint.MaxValue)
                return;

            if (*(uint *)buffer != RIM_TYPEMOUSE)
                return;

            byte* mouse = buffer + headerSize;
            if ((*(ushort *)mouse & MOUSE_MOVE_ABSOLUTE) != 0)
                return;

            HostEventQueue.EnqueueRawMouseMotion(*(int *)(mouse + 12), *(int *)(mouse + 16));
        }

        private static void ApplyInitialState(WindowsWindow window, WindowOptions options)
        {
            if (options.Center)
            {
                CenterWindow(window);
            }

            window.State = options.State;

            if (!options.Visible)
                window.Hide();
        }

        private static void CenterWindow(WindowsWindow window)
        {
            RECT rect;
            if (!GetWindowRect(window.NativeHandle, out rect))
                return;

            int width = rect.Right - rect.Left;
            int height = rect.Bottom - rect.Top;
            int screenWidth = GetSystemMetrics(0);
            int screenHeight = GetSystemMetrics(1);

            int x = Math.Max((screenWidth - width) / 2, 0);
            int y = Math.Max((screenHeight - height) / 2, 0);

            SetWindowPos(window.NativeHandle, IntPtr.Zero, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }

        private static IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            if (Windows.TryGetValue(hwnd, out WindowsWindow? window))
                return window.HandleMessage(msg, wParam, lParam);

            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }

        internal static bool CloseWindowHandle(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero)
                return false;

            if (!Windows.TryRemove(hwnd, out _))
                return false;

            return DestroyWindowNative(hwnd);
        }

        internal void RemoveWindow(IntPtr hwnd)
        {
            Windows.TryRemove(hwnd, out _);
        }

        internal void UpdateWindowText(IntPtr hwnd, string text)
        {
            SetWindowTextW(hwnd, text ?? string.Empty);
        }

        internal void UpdateWindowSize(IntPtr hwnd, uint style, int width, int height)
        {
            RECT rect;
            if (!GetWindowRect(hwnd, out rect))
                return;

            ResolveOuterFromClient(style, 0, Math.Max(width, 1), Math.Max(height, 1), FrameDpi(hwnd), out int outerWidth, out int outerHeight);

            if (rect.Right - rect.Left == outerWidth && rect.Bottom - rect.Top == outerHeight)
                return;

            SetWindowPos(hwnd, IntPtr.Zero, rect.Left, rect.Top, outerWidth, outerHeight, SWP_NOZORDER | SWP_NOACTIVATE);
        }

        private void ApplyDpiAwareness(DpiAwareness awareness)
        {
            if (_dpiAwarenessApplied && _dpiAwareness == awareness)
                return;

            IntPtr context = awareness switch
            {
                DpiAwareness.PerMonitor => DpiContextPerMonitorAwareV2,
                DpiAwareness.System => DpiContextSystemAware,
                _ => DpiContextUnaware,
            };

            try
            {
                if (SetThreadDpiAwarenessContext(context) == IntPtr.Zero)
                    return;
            }
            catch (EntryPointNotFoundException)
            {
                return;
            }

            _dpiAwareness = awareness;
            _dpiAwarenessApplied = true;
        }

        private uint FrameDpi(IntPtr hwnd)
        {
            if (_dpiAwareness == DpiAwareness.Unaware)
                return 0;

            if (hwnd != IntPtr.Zero)
            {
                uint windowDpi = GetDpiForWindow(hwnd);
                if (windowDpi != 0)
                    return windowDpi;
            }

            return HostDisplayMetrics.SystemDpi;
        }

        private static void ResolveOuterFromClient(uint style, uint exStyle, int clientWidth, int clientHeight, uint dpi, out int outerWidth, out int outerHeight)
        {
            RECT rect = new RECT { Left = 0, Top = 0, Right = clientWidth, Bottom = clientHeight };
            if (AdjustFrameRect(ref rect, style, exStyle, dpi))
            {
                outerWidth = Math.Max(rect.Right - rect.Left, 1);
                outerHeight = Math.Max(rect.Bottom - rect.Top, 1);
                return;
            }

            outerWidth = Math.Max(clientWidth, 1);
            outerHeight = Math.Max(clientHeight, 1);
        }

        private static bool AdjustFrameRect(ref RECT rect, uint style, uint exStyle, uint dpi)
        {
            if (dpi != 0)
            {
                try
                {
                    if (AdjustWindowRectExForDpi(ref rect, style, false, exStyle, dpi))
                        return true;
                }
                catch (EntryPointNotFoundException)
                {
                }
            }

            return AdjustWindowRectEx(ref rect, style, false, exStyle);
        }

        internal void UpdateWindowVisibility(IntPtr hwnd, bool visible)
        {
            ShowWindow(hwnd, visible ? SW_SHOW : SW_HIDE);
        }

        internal void UpdateWindowState(IntPtr hwnd, WindowState state)
        {
            switch (state)
            {
                case WindowState.Minimized:
                    ShowWindow(hwnd, SW_MINIMIZE);
                    break;
                case WindowState.Maximized:
                    ShowWindow(hwnd, SW_MAXIMIZE);
                    break;
                case WindowState.Fullscreen:
                    ShowWindow(hwnd, SW_MAXIMIZE);
                    break;
                default:
                    ShowWindow(hwnd, SW_RESTORE);
                    break;
            }
        }

        internal uint ApplyDecorations(IntPtr hwnd, uint currentStyle, bool decorated, bool resizable)
        {
            uint style = currentStyle;

            if (decorated)
                style |= WS_OVERLAPPEDWINDOW;
            else
                style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);

            if (resizable)
                style |= WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
            else
                style &= ~(WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);

            if (style == currentStyle)
                return style;

            SetWindowLongPtrW(hwnd, GWL_STYLE, (IntPtr)style);
            SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
            return style;
        }

        public void RenderText(IntPtr windowHandle, ulong hwnd, IntPtr font, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options, GdiClipRect[] clip)
        {
            if (string.IsNullOrEmpty(text) || !Windows.TryGetValue(windowHandle, out WindowsWindow? window))
                return;

            IntPtr hdc = window.EnsureTextDeviceContext();
            if (hdc == IntPtr.Zero)
                return;

            window.ApplyClip(hdc, clip);

            IntPtr previous = font != IntPtr.Zero ? SelectObject(hdc, font) : IntPtr.Zero;
            RECT rect = new RECT { Left = rectLeft, Top = rectTop, Right = rectRight, Bottom = rectBottom };
            ExtTextOutW(hdc, x, y, options, ref rect, text, (uint)text.Length, IntPtr.Zero);

            if (previous != IntPtr.Zero)
                SelectObject(hdc, previous);
        }

        public unsafe void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive)
        {
            if (!Windows.TryGetValue(windowHandle, out WindowsWindow? window))
                return;

            IntPtr hdc = window.EnsureDeviceContext();
            if (hdc == IntPtr.Zero)
                return;

            window.ApplyClip(hdc, primitive.Clip);
            window.SelectPen(primitive.HasPen
                ? GetOrCreatePen(primitive.Pen.Width, unchecked((int)primitive.Pen.ColorRef))
                : StockBlackPen);

            window.SelectBrush(primitive.HasBrush
                ? GetOrCreateBrush(unchecked((int)primitive.Brush.ColorRef))
                : StockWhiteBrush);

            switch (primitive.Kind)
            {
                case GdiPrimitiveKind.Line:
                    MoveToEx(hdc, primitive.X1, primitive.Y1, IntPtr.Zero);
                    LineTo(hdc, primitive.X2, primitive.Y2);
                    break;

                case GdiPrimitiveKind.FillRect:
                    PatBlt(hdc, primitive.X1, primitive.Y1, primitive.X2 - primitive.X1, primitive.Y2 - primitive.Y1, primitive.Rop);
                    break;

                case GdiPrimitiveKind.Rectangle:
                    Rectangle(hdc, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2);
                    break;

                case GdiPrimitiveKind.Ellipse:
                    Ellipse(hdc, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2);
                    break;

                case GdiPrimitiveKind.RoundRect:
                    RoundRect(hdc, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2, primitive.RoundedWidth, primitive.RoundedHeight);
                    break;

                case GdiPrimitiveKind.Polygon:
                case GdiPrimitiveKind.Polyline:
                    DrawPoly(hdc, primitive);
                    break;

                case GdiPrimitiveKind.Blit:
                    DrawBlit(hdc, primitive);
                    break;

                // BitBlt handles an overlapping copy.
                case GdiPrimitiveKind.Copy:
                    BitBlt(hdc, primitive.X1, primitive.Y1, primitive.X2 - primitive.X1, primitive.Y2 - primitive.Y1,
                        hdc, primitive.SourceX, primitive.SourceY, SRCCOPY);
                    break;
            }
        }

        private static unsafe void DrawBlit(IntPtr hdc, in GdiPrimitive primitive)
        {
            uint[] pixels = primitive.Pixels;
            if (pixels == null || primitive.SourceWidth <= 0 || primitive.SourceHeight <= 0)
                return;

            if (pixels.Length < primitive.SourceWidth * primitive.SourceHeight)
                return;

            BITMAPINFOHEADER header = new BITMAPINFOHEADER
            {
                biSize = (uint)sizeof(BITMAPINFOHEADER),
                biWidth = primitive.SourceWidth,
                // A negative height makes the rows read top-down.
                biHeight = -primitive.SourceHeight,
                biPlanes = 1,
                biBitCount = 32,
                biCompression = 0,
            };

            fixed (uint* bits = pixels)
            {
                StretchDIBits(hdc, primitive.X1, primitive.Y1, primitive.X2 - primitive.X1, primitive.Y2 - primitive.Y1,
                    0, 0, primitive.SourceWidth, primitive.SourceHeight, bits, ref header, 0, primitive.Rop);
            }
        }

        private static unsafe void DrawPoly(IntPtr hdc, in GdiPrimitive primitive)
        {
            GdiPoint[] points = primitive.Points;
            if (points == null || points.Length == 0)
                return;

            POINT[] rented = points.Length > StackPointLimit ? ArrayPool<POINT>.Shared.Rent(points.Length) : null;
            Span<POINT> native = rented != null ? rented.AsSpan(0, points.Length) : stackalloc POINT[points.Length];

            for (int i = 0; i < points.Length; i++)
            {
                native[i].X = points[i].X;
                native[i].Y = points[i].Y;
            }

            fixed (POINT* buffer = native)
            {
                if (primitive.Kind == GdiPrimitiveKind.Polygon)
                    Polygon(hdc, buffer, points.Length);
                else
                    Polyline(hdc, buffer, points.Length);
            }

            if (rented != null)
                ArrayPool<POINT>.Shared.Return(rented);
        }

        public unsafe bool TranslateVirtualKey(uint virtualKey, uint scanCode, out char character)
        {
            character = '\0';

            Span<byte> keyboardState = stackalloc byte[256];
            fixed (byte* state = keyboardState)
            {
                if (!GetKeyboardState(state))
                    return false;

                char* buffer = stackalloc char[8];
                if (ToUnicode(virtualKey, scanCode, state, buffer, 8, 0) <= 0)
                    return false;

                character = buffer[0];
            }

            return true;
        }

        public bool MeasureText(IntPtr font, string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            if (text == null)
                text = string.Empty;

            lock (MetricsLock)
            {
                IntPtr hdc = EnsureMetricsDc();
                if (hdc == IntPtr.Zero)
                    return false;

                IntPtr previous = font != IntPtr.Zero ? SelectObject(hdc, font) : IntPtr.Zero;
                bool measured = GetTextExtentPoint32W(hdc, text, text.Length, out SIZE size);
                bool haveHeight = false;
                int emptyHeight = 0;

                if (text.Length == 0 && GetTextMetricsW(hdc, out TEXTMETRICW empty))
                {
                    haveHeight = true;
                    emptyHeight = empty.tmHeight;
                }

                if (previous != IntPtr.Zero)
                    SelectObject(hdc, previous);

                if (!measured)
                    return false;

                width = size.cx;
                height = haveHeight ? emptyHeight : size.cy;
            }

            return true;
        }

        public IntPtr CreateFont(in FontDescription description)
        {
            LOGFONTW logFont = new LOGFONTW
            {
                lfHeight = description.Height,
                lfWidth = description.Width,
                lfWeight = description.Weight,
                lfItalic = description.Italic ? (byte)1 : (byte)0,
                lfUnderline = description.Underline ? (byte)1 : (byte)0,
                lfStrikeOut = description.StrikeOut ? (byte)1 : (byte)0,
                lfCharSet = description.CharSet,
                lfPitchAndFamily = description.PitchAndFamily,
                lfQuality = CleartypeQuality,
                lfFaceName = description.FaceName ?? string.Empty,
            };

            return CreateFontIndirectW(ref logFont);
        }

        public void DeleteFont(IntPtr font)
        {
            if (font != IntPtr.Zero)
                DeleteObject(font);
        }

        public IReadOnlyList<FontFamilyData> EnumerateFontFamilies(string faceName, byte charSet)
        {
            List<FontFamilyData> faces = new List<FontFamilyData>();

            lock (MetricsLock)
            {
                IntPtr hdc = EnsureMetricsDc();
                if (hdc == IntPtr.Zero)
                    return faces;

                LOGFONTW query = new LOGFONTW
                {
                    lfCharSet = charSet,
                    lfFaceName = faceName ?? string.Empty,
                };

                EnumFontFamiliesExW(hdc, ref query, (logFont, textMetric, fontType, _) =>
                {
                    ENUMLOGFONTEXW enumerated = Marshal.PtrToStructure<ENUMLOGFONTEXW>(logFont);
                    NEWTEXTMETRICW metrics = Marshal.PtrToStructure<NEWTEXTMETRICW>(textMetric);

                    faces.Add(new FontFamilyData
                    {
                        FaceName = enumerated.elfLogFont.lfFaceName,
                        FullName = enumerated.elfFullName,
                        Style = enumerated.elfStyle,
                        CharSet = enumerated.elfLogFont.lfCharSet,
                        PitchAndFamily = enumerated.elfLogFont.lfPitchAndFamily,
                        Weight = enumerated.elfLogFont.lfWeight,
                        Italic = enumerated.elfLogFont.lfItalic != 0,
                        FontType = fontType,
                        Metrics = ToMetricsData(metrics),
                        NtmFlags = metrics.ntmFlags,
                        SizeEm = metrics.ntmSizeEM,
                        CellHeight = metrics.ntmCellHeight,
                        AvgWidth = metrics.ntmAvgWidth,
                    });

                    return 1;
                }, IntPtr.Zero, 0);
            }

            return faces;
        }

        private static TextMetricsData ToMetricsData(in NEWTEXTMETRICW native)
        {
            return new TextMetricsData
            {
                Height = native.tmHeight,
                Ascent = native.tmAscent,
                Descent = native.tmDescent,
                InternalLeading = native.tmInternalLeading,
                ExternalLeading = native.tmExternalLeading,
                AveCharWidth = native.tmAveCharWidth,
                MaxCharWidth = native.tmMaxCharWidth,
                Weight = native.tmWeight,
                Overhang = native.tmOverhang,
                DigitizedAspectX = native.tmDigitizedAspectX,
                DigitizedAspectY = native.tmDigitizedAspectY,
                FirstChar = native.tmFirstChar,
                LastChar = native.tmLastChar,
                DefaultChar = native.tmDefaultChar,
                BreakChar = native.tmBreakChar,
                Italic = native.tmItalic,
                Underlined = native.tmUnderlined,
                StruckOut = native.tmStruckOut,
                PitchAndFamily = native.tmPitchAndFamily,
                CharSet = native.tmCharSet,
            };
        }

        public bool GetTextMetrics(IntPtr font, out TextMetricsData metrics)
        {
            metrics = default;

            lock (MetricsLock)
            {
                IntPtr hdc = EnsureMetricsDc();
                if (hdc == IntPtr.Zero)
                    return false;

                IntPtr previous = font != IntPtr.Zero ? SelectObject(hdc, font) : IntPtr.Zero;
                bool read = GetTextMetricsW(hdc, out TEXTMETRICW native);

                if (previous != IntPtr.Zero)
                    SelectObject(hdc, previous);

                if (!read)
                    return false;

                metrics.Height = native.tmHeight;
                metrics.Ascent = native.tmAscent;
                metrics.Descent = native.tmDescent;
                metrics.InternalLeading = native.tmInternalLeading;
                metrics.ExternalLeading = native.tmExternalLeading;
                metrics.AveCharWidth = native.tmAveCharWidth;
                metrics.MaxCharWidth = native.tmMaxCharWidth;
                metrics.Weight = native.tmWeight;
                metrics.Overhang = native.tmOverhang;
                metrics.DigitizedAspectX = native.tmDigitizedAspectX;
                metrics.DigitizedAspectY = native.tmDigitizedAspectY;
                metrics.FirstChar = native.tmFirstChar;
                metrics.LastChar = native.tmLastChar;
                metrics.DefaultChar = native.tmDefaultChar;
                metrics.BreakChar = native.tmBreakChar;
                metrics.Italic = native.tmItalic;
                metrics.Underlined = native.tmUnderlined;
                metrics.StruckOut = native.tmStruckOut;
                metrics.PitchAndFamily = native.tmPitchAndFamily;
                metrics.CharSet = native.tmCharSet;
            }

            return true;
        }

        public unsafe bool RasterizeText(IntPtr font, string text, Span<uint> pixels, int width, int height,
            int x, int y, uint textColor, uint backColor, bool opaque)
        {
            int Count = width * height;
            if (width <= 0 || height <= 0 || pixels.Length < Count)
                return false;

            lock (MetricsLock)
            {
                if (!_raster.Ensure(width, height))
                    return false;

                IntPtr hdc = _raster.Dc;
                Span<uint> surface = new Span<uint>((void*)_raster.Bits, Count);
                pixels.Slice(0, Count).CopyTo(surface);

                IntPtr previousFont = font != IntPtr.Zero ? SelectObject(hdc, font) : IntPtr.Zero;
                SetTextColor(hdc, unchecked((int)(textColor & 0x00FFFFFF)));
                SetBkColor(hdc, unchecked((int)(backColor & 0x00FFFFFF)));
                SetBkMode(hdc, opaque ? OPAQUE : TRANSPARENT);

                RECT rect = new RECT { Left = 0, Top = 0, Right = width, Bottom = height };
                bool drawn = ExtTextOutW(hdc, x, y, opaque ? ETO_OPAQUE : 0u, ref rect,
                    text ?? string.Empty, (uint)(text?.Length ?? 0), IntPtr.Zero);

                // The DIB bits are only current once the batch is flushed.
                GdiFlush();

                if (previousFont != IntPtr.Zero)
                    SelectObject(hdc, previousFont);

                if (!drawn)
                    return false;

                surface.CopyTo(pixels.Slice(0, Count));
            }

            return true;
        }

        // Use in place through the owner's field. A copy shares the owner's GDI objects.
        private struct DibSurface
        {
            private IntPtr _bitmap;
            private IntPtr _previousBitmap;

            public IntPtr Dc { get; private set; }

            public IntPtr Bits { get; private set; }

            public int Width { get; private set; }

            public int Height { get; private set; }

            public readonly bool Matches(int width, int height) => Dc != IntPtr.Zero && Width == width && Height == height;

            public unsafe bool Ensure(int width, int height)
            {
                if (Matches(width, height))
                    return true;

                Release();

                IntPtr screenDc = GetDC(IntPtr.Zero);
                if (screenDc == IntPtr.Zero)
                    return false;

                IntPtr memoryDc = CreateCompatibleDC(screenDc);
                ReleaseDC(IntPtr.Zero, screenDc);
                if (memoryDc == IntPtr.Zero)
                    return false;

                BITMAPINFOHEADER header = default;
                header.biSize = (uint)sizeof(BITMAPINFOHEADER);
                header.biWidth = width;
                header.biHeight = -height;
                header.biPlanes = 1;
                header.biBitCount = 32;
                header.biCompression = BI_RGB;

                IntPtr dib = CreateDIBSection(memoryDc, ref header, DIB_RGB_COLORS, out IntPtr bits, IntPtr.Zero, 0);
                if (dib == IntPtr.Zero || bits == IntPtr.Zero)
                {
                    if (dib != IntPtr.Zero)
                        DeleteObject(dib);
                    DeleteDC(memoryDc);
                    return false;
                }

                _previousBitmap = SelectObject(memoryDc, dib);
                _bitmap = dib;
                Dc = memoryDc;
                Bits = bits;
                Width = width;
                Height = height;
                return true;
            }

            public void Release()
            {
                if (Dc == IntPtr.Zero)
                    return;

                if (_previousBitmap != IntPtr.Zero)
                    SelectObject(Dc, _previousBitmap);

                if (_bitmap != IntPtr.Zero)
                    DeleteObject(_bitmap);

                DeleteDC(Dc);
                this = default;
            }
        }

        private static IntPtr EnsureMetricsDc()
        {
            if (_metricsDc != IntPtr.Zero)
                return _metricsDc;

            IntPtr screenDc = GetDC(IntPtr.Zero);
            if (screenDc == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr memoryDc = CreateCompatibleDC(screenDc);
            ReleaseDC(IntPtr.Zero, screenDc);
            if (memoryDc == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr font = GetStockObject(STOCK_OBJECT_DEFAULT_GUI_FONT);
            if (font != IntPtr.Zero)
                _metricsPreviousFont = SelectObject(memoryDc, font);

            _metricsFont = font;
            _metricsDc = memoryDc;
            return _metricsDc;
        }

        private sealed class WindowsWindow : ITopLevelWindow
        {
            private readonly WindowsWinManager _manager;
            private readonly IntPtr _hwnd;
            private readonly ulong _guestWindow;
            private bool _disposed;
            private string _title;
            private int _width;
            private int _height;
            private bool _visible;
            private WindowState _state;
            private bool _decorated;
            private readonly bool _resizable;
            private uint _style;
            private uint _exStyle;
            private bool _cursorVisible = true;
            private bool _cursorClipped;
            private RECT _cursorClip;

            private IntPtr _hdc;
            private GdiClipRect[] _clip;
            private IntPtr _selectedPen;
            private IntPtr _selectedBrush;
            private bool _textStateApplied;

            private bool _activated;
            private bool _layeredByUpdate;
            private bool _layeredByAttributes;
            private int _boundsX;
            private int _boundsY;
            private int _boundsWidth;
            private int _boundsHeight;

            private DibSurface _layered;

            internal WindowsWindow(WindowsWinManager manager, IntPtr hwnd, WindowOptions options)
            {
                _manager = manager;
                _hwnd = hwnd;
                _title = string.Concat(options.Title, " - Brovan") ?? string.Empty;
                _width = Math.Max(options.Width, 1);
                _height = Math.Max(options.Height, 1);
                _visible = options.Visible;
                _state = options.State;
                _decorated = options.Decorated;
                _resizable = options.Resizable;

                _style = unchecked((uint)GetWindowLongPtrW(hwnd, GWL_STYLE).ToInt64());
                _style = _manager.ApplyDecorations(_hwnd, _style, _decorated, _resizable);
            }

            internal WindowsWindow(WindowsWinManager manager, IntPtr hwnd, in TopLevelFrame frame, uint style, uint exStyle)
            {
                _manager = manager;
                _hwnd = hwnd;
                _guestWindow = frame.Window;
                _title = FormatTitle(frame.Title);
                _width = Math.Max(frame.ClientWidth, 0);
                _height = Math.Max(frame.ClientHeight, 0);
                _state = WindowState.Normal;
                _decorated = (style & WS_CAPTION) == WS_CAPTION;
                _resizable = (style & WS_THICKFRAME) != 0;
                _style = style;
                _exStyle = exStyle;
                _boundsX = frame.ClientX;
                _boundsY = frame.ClientY;
                _boundsWidth = _width;
                _boundsHeight = _height;
            }

            internal static string FormatTitle(string title)
            {
                return string.IsNullOrEmpty(title) ? "Brovan" : string.Concat(title, " - Brovan");
            }

            private bool IsTopLevel => _guestWindow != 0;

            private bool EchoesGuest => IsTopLevel && _manager._applyingGuestState != 0;

            internal IntPtr EnsureDeviceContext()
            {
                if (_hdc == IntPtr.Zero && !_disposed)
                    _hdc = GetDC(_hwnd);

                return _hdc;
            }

            internal IntPtr EnsureTextDeviceContext()
            {
                IntPtr hdc = EnsureDeviceContext();
                if (hdc == IntPtr.Zero || _textStateApplied)
                    return hdc;

                IntPtr font = GetStockObject(STOCK_OBJECT_DEFAULT_GUI_FONT);
                if (font != IntPtr.Zero)
                    SelectObject(hdc, font);

                SetTextColor(hdc, 0x00000000);
                SetBkMode(hdc, TRANSPARENT);
                _textStateApplied = true;
                return hdc;
            }

            internal unsafe void ApplyClip(IntPtr hdc, GdiClipRect[] clip)
            {
                if (ReferenceEquals(clip, _clip))
                    return;

                _clip = clip;
                if (clip == null)
                {
                    SelectClipRgn(hdc, IntPtr.Zero);
                    return;
                }

                RGNDATAHEADER header = new RGNDATAHEADER
                {
                    Size = (uint)sizeof(RGNDATAHEADER),
                    Type = RDH_RECTANGLES,
                    Count = (uint)clip.Length,
                    RegionSize = (uint)(clip.Length * sizeof(GdiClipRect)),
                };

                for (int i = 0; i < clip.Length; i++)
                {
                    GdiClipRect rect = clip[i];
                    header.Bound = i == 0
                        ? new RECT { Left = rect.Left, Top = rect.Top, Right = rect.Right, Bottom = rect.Bottom }
                        : new RECT
                        {
                            Left = Math.Min(header.Bound.Left, rect.Left),
                            Top = Math.Min(header.Bound.Top, rect.Top),
                            Right = Math.Max(header.Bound.Right, rect.Right),
                            Bottom = Math.Max(header.Bound.Bottom, rect.Bottom),
                        };
                }

                int bytes = sizeof(RGNDATAHEADER) + (int)header.RegionSize;
                byte[] rented = clip.Length > StackClipLimit ? ArrayPool<byte>.Shared.Rent(bytes) : null;
                Span<byte> data = rented != null ? rented.AsSpan(0, bytes) : stackalloc byte[bytes];

                IntPtr region;
                try
                {
                    MemoryMarshal.Write(data, in header);
                    MemoryMarshal.AsBytes(clip.AsSpan()).CopyTo(data.Slice(sizeof(RGNDATAHEADER)));

                    fixed (byte* buffer = data)
                        region = ExtCreateRegion(IntPtr.Zero, (uint)bytes, buffer);
                }
                finally
                {
                    if (rented != null)
                        ArrayPool<byte>.Shared.Return(rented);
                }

                if (region == IntPtr.Zero)
                    return;

                SelectClipRgn(hdc, region);
                DeleteObject(region);
            }

            internal void SelectPen(IntPtr pen)
            {
                if (pen == IntPtr.Zero || pen == _selectedPen)
                    return;

                SelectObject(_hdc, pen);
                _selectedPen = pen;
            }

            internal void SelectBrush(IntPtr brush)
            {
                if (brush == IntPtr.Zero || brush == _selectedBrush)
                    return;

                SelectObject(_hdc, brush);
                _selectedBrush = brush;
            }

            public string Title
            {
                get => _title;
                set
                {
                    EnsureAlive();
                    _title = IsTopLevel ? FormatTitle(value) : string.Concat(value, " - Brovan");
                    _manager.UpdateWindowText(_hwnd, _title);
                }
            }

            public int Width
            {
                get => _width;
                set
                {
                    EnsureAlive();
                    _width = Math.Max(value, 1);
                    _manager.UpdateWindowSize(_hwnd, _style, _width, _height);
                }
            }

            public int Height
            {
                get => _height;
                set
                {
                    EnsureAlive();
                    _height = Math.Max(value, 1);
                    _manager.UpdateWindowSize(_hwnd, _style, _width, _height);
                }
            }

            public bool Visible
            {
                get => _visible;
                set
                {
                    EnsureAlive();
                    _visible = value;
                    _manager.UpdateWindowVisibility(_hwnd, _visible);
                    if (_visible)
                        _manager.UpdateWindowState(_hwnd, _state);
                }
            }

            public WindowState State
            {
                get => _state;
                set
                {
                    EnsureAlive();
                    _state = value;

                    if (IsTopLevel)
                    {
                        if (_visible)
                            ShowInState();

                        return;
                    }

                    if (_visible)
                        _manager.UpdateWindowState(_hwnd, _state);
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
                    _style = _manager.ApplyDecorations(_hwnd, _style, _decorated, _resizable);
                }
            }

            public void SetFrame(uint style, uint exStyle)
            {
                EnsureAlive();

                uint current = unchecked((uint)GetWindowLongPtrW(_hwnd, GWL_STYLE).ToInt64());
                uint hostStyle = HostStyle(style) | (current & HostWindowState);
                uint hostExStyle = HostExStyle(exStyle);
                bool topmostChanged = ((hostExStyle ^ _exStyle) & WS_EX_TOPMOST) != 0;

                using (new GuestApplyScope(_manager))
                {
                    SetWindowLongPtrW(_hwnd, GWL_STYLE, (IntPtr)hostStyle);
                    SetWindowLongPtrW(_hwnd, GWL_EXSTYLE, (IntPtr)hostExStyle);

                    // WS_EX_TOPMOST changes only through SetWindowPos.
                    if (topmostChanged)
                    {
                        SetWindowPos(_hwnd, (hostExStyle & WS_EX_TOPMOST) != 0 ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
                    }

                    SetWindowPos(_hwnd, IntPtr.Zero, 0, 0, 0, 0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_FRAMECHANGED);
                }

                _style = hostStyle & ~HostWindowState;
                _exStyle = hostExStyle;
                _decorated = (_style & WS_CAPTION) == WS_CAPTION;

                if ((hostExStyle & WS_EX_LAYERED) == 0)
                    ForgetLayeredMode();
            }

            private void ForgetLayeredMode()
            {
                _layeredByUpdate = false;
                _layeredByAttributes = false;
                _layered.Release();
            }

            public void SetOwner(ITopLevelWindow owner)
            {
                EnsureAlive();
                SetWindowLongPtrW(_hwnd, GWLP_HWNDPARENT, owner?.NativeHandle ?? IntPtr.Zero);
            }

            public void SetClientBounds(int x, int y, int width, int height)
            {
                EnsureAlive();

                _boundsX = x;
                _boundsY = y;
                _boundsWidth = width;
                _boundsHeight = height;

                // The host picks its own maximized rectangle for a window without a caption, so the guest's is applied.
                if (_state == WindowState.Normal || (_state == WindowState.Maximized && IsZoomed(_hwnd)))
                    ApplyBounds();
            }

            // AdjustWindowRectEx adds a padded border a fixed frame does not draw. Measure the live frame.
            private void ApplyBounds()
            {
                RECT outer;
                if (TryGetFrameInsets(out int left, out int top, out int right, out int bottom))
                {
                    outer = new RECT
                    {
                        Left = _boundsX - left,
                        Top = _boundsY - top,
                        Right = _boundsX + Math.Max(_boundsWidth, 0) + right,
                        Bottom = _boundsY + Math.Max(_boundsHeight, 0) + bottom,
                    };
                }
                else
                {
                    outer = ClientToOuter(_style, _exStyle, _boundsX, _boundsY, _boundsWidth, _boundsHeight, _manager.FrameDpi(_hwnd));
                }

                using (new GuestApplyScope(_manager))
                {
                    SetWindowPos(_hwnd, IntPtr.Zero, outer.Left, outer.Top, outer.Right - outer.Left, outer.Bottom - outer.Top,
                        SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
                }

                ReportGeometry(_boundsX, _boundsY, _boundsWidth, _boundsHeight);
            }

            public void SetEnabled(bool enabled)
            {
                EnsureAlive();
                EnableWindow(_hwnd, enabled);
            }

            public void SetShown(bool shown)
            {
                EnsureAlive();

                if (_visible == shown)
                    return;

                _visible = shown;
                ShowInState();
            }

            // Foreground lock. Only the first activation can take the foreground from another process.
            public void Activate()
            {
                EnsureAlive();

                if (!_visible)
                    return;

                IntPtr foreground = GetForegroundWindow();
                if (_activated && foreground != IntPtr.Zero && !_manager.IsHostWindow(foreground))
                    return;

                _activated = true;

                using (new GuestApplyScope(_manager))
                    SetForegroundWindow(_hwnd);
            }

            public void SetLayeredAttributes(uint colorKey, byte alpha, uint flags)
            {
                EnsureAlive();

                if ((_exStyle & WS_EX_LAYERED) == 0)
                    return;

                if (_layeredByUpdate)
                    ForgetLayeredMode();

                SetLayeredWindowAttributes(_hwnd, colorKey, alpha, flags);
                _layeredByAttributes = true;
            }

            public unsafe void UpdateLayered(LayeredUpdate update)
            {
                EnsureAlive();

                if ((_exStyle & WS_EX_LAYERED) == 0 || update.Width <= 0 || update.Height <= 0)
                    return;

                // NT: UpdateLayeredWindow fails after SetLayeredWindowAttributes until the style is cleared and set again.
                if (_layeredByAttributes)
                {
                    using (new GuestApplyScope(_manager))
                    {
                        SetWindowLongPtrW(_hwnd, GWL_EXSTYLE, (IntPtr)(_exStyle & ~WS_EX_LAYERED));
                        SetWindowLongPtrW(_hwnd, GWL_EXSTYLE, (IntPtr)_exStyle);
                    }

                    ForgetLayeredMode();
                }

                _layeredByUpdate = true;

                if (update.Pixels != null && _layered.Ensure(update.Width, update.Height))
                {
                    int left = Math.Max(update.DirtyLeft, 0);
                    int top = Math.Max(update.DirtyTop, 0);
                    int right = Math.Min(update.DirtyLeft + update.DirtyWidth, update.Width);
                    int bottom = Math.Min(update.DirtyTop + update.DirtyHeight, update.Height);

                    if (right > left && bottom > top && update.Pixels.Length >= update.DirtyWidth * update.DirtyHeight)
                    {
                        uint* surface = (uint*)_layered.Bits;
                        for (int row = top; row < bottom; row++)
                        {
                            ReadOnlySpan<uint> source = update.Pixels.AsSpan((row - update.DirtyTop) * update.DirtyWidth + (left - update.DirtyLeft), right - left);
                            source.CopyTo(new Span<uint>(surface + (long)row * _layered.Width + left, right - left));
                        }
                    }
                }

                bool haveSurface = _layered.Matches(update.Width, update.Height);

                POINT destination = new POINT { X = update.X, Y = update.Y };
                SIZE size = new SIZE { cx = update.Width, cy = update.Height };
                POINT source0 = new POINT { X = 0, Y = 0 };
                BLENDFUNCTION blend = new BLENDFUNCTION
                {
                    BlendOp = AC_SRC_OVER,
                    BlendFlags = 0,
                    SourceConstantAlpha = update.ConstantAlpha,
                    AlphaFormat = update.AlphaFormat,
                };

                using (new GuestApplyScope(_manager))
                {
                    // NT: with no source DC, UpdateLayeredWindow fails a size or source point.
                    if (!haveSurface)
                    {
                        SetWindowPos(_hwnd, IntPtr.Zero, update.X, update.Y, update.Width, update.Height,
                            SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
                    }

                    UpdateLayeredWindow(_hwnd, IntPtr.Zero, haveSurface ? &destination : null, haveSurface ? &size : null,
                        haveSurface ? _layered.Dc : IntPtr.Zero, haveSurface ? &source0 : null, update.ColorKey, &blend,
                        update.Flags & (ULW_COLORKEY | ULW_ALPHA | ULW_OPAQUE));
                }
            }

            private void ShowInState()
            {
                int command;
                if (!_visible)
                    command = SW_HIDE;
                else if (_state == WindowState.Minimized)
                    command = SW_SHOWMINNOACTIVE;
                else if (_state == WindowState.Maximized || _state == WindowState.Fullscreen)
                    command = SW_MAXIMIZE;
                else if (IsIconic(_hwnd) || IsZoomed(_hwnd))
                    command = SW_SHOWNOACTIVATE;
                else
                    command = SW_SHOWNA;

                using (new GuestApplyScope(_manager))
                    ShowWindow(_hwnd, command);

                if (!_visible)
                    return;

                if (_state == WindowState.Normal)
                    ApplyBounds();
                else
                    ReportGeometry(int.MinValue, int.MinValue, -1, -1);
            }

            private void ReportGeometry(int x, int y, int width, int height)
            {
                if (IsIconic(_hwnd))
                {
                    HostEventQueue.Enqueue(WM_SIZE, SIZE_MINIMIZED, 0, _guestWindow);
                    return;
                }

                if (!GetClientRect(_hwnd, out RECT client))
                    return;

                POINT origin = new POINT { X = 0, Y = 0 };
                if (!ClientToScreen(_hwnd, ref origin))
                    return;

                if (origin.X != x || origin.Y != y)
                    HostEventQueue.Enqueue(WM_MOVE, 0, HostEventQueue.MakeLParam(origin.X, origin.Y), _guestWindow);

                int clientWidth = client.Right - client.Left;
                int clientHeight = client.Bottom - client.Top;
                if (clientWidth != width || clientHeight != height)
                {
                    uint sizeType = IsZoomed(_hwnd) ? SIZE_MAXIMIZED : 0;
                    HostEventQueue.Enqueue(WM_SIZE, sizeType, HostEventQueue.MakeLParam(clientWidth, clientHeight), _guestWindow);
                }
            }

            private bool TryGetFrameInsets(out int left, out int top, out int right, out int bottom)
            {
                left = top = right = bottom = 0;

                if (IsIconic(_hwnd) || IsZoomed(_hwnd) || !GetWindowRect(_hwnd, out RECT window) || !GetClientRect(_hwnd, out RECT client))
                    return false;

                POINT origin = new POINT { X = 0, Y = 0 };
                if (!ClientToScreen(_hwnd, ref origin))
                    return false;

                left = origin.X - window.Left;
                top = origin.Y - window.Top;
                right = window.Right - (origin.X + client.Right);
                bottom = window.Bottom - (origin.Y + client.Bottom);
                return left >= 0 && top >= 0 && right >= 0 && bottom >= 0;
            }

            public void WarpCursor(int clientX, int clientY)
            {
                EnsureAlive();

                POINT Point = new POINT { X = clientX, Y = clientY };
                if (ClientToScreen(_hwnd, ref Point))
                    SetCursorPos(Point.X, Point.Y);
            }

            // The host clip is global, so only the window that holds it sets or releases it.
            public void SetCursorClip(bool enabled, int clientLeft, int clientTop, int clientRight, int clientBottom)
            {
                EnsureAlive();

                if (!enabled)
                {
                    ReleaseCursorClip();
                    _cursorClipped = false;
                    return;
                }

                _cursorClipped = true;
                _cursorClip = new RECT { Left = clientLeft, Top = clientTop, Right = clientRight, Bottom = clientBottom };
                ApplyCursorClip();
            }

            // NT drops the clip on deactivation, so it is applied again on activate, move and resize.
            private void ApplyCursorClip()
            {
                if (!_cursorClipped)
                    return;

                if (!GetClientRect(_hwnd, out RECT Client))
                    return;

                int Left = Math.Max(_cursorClip.Left, Client.Left);
                int Top = Math.Max(_cursorClip.Top, Client.Top);
                int Right = Math.Min(_cursorClip.Right, Client.Right);
                int Bottom = Math.Min(_cursorClip.Bottom, Client.Bottom);

                if (Right - Left < 1 || Bottom - Top < 1)
                    return;

                POINT TopLeft = new POINT { X = Left, Y = Top };
                POINT BottomRight = new POINT { X = Right, Y = Bottom };
                if (!ClientToScreen(_hwnd, ref TopLeft) || !ClientToScreen(_hwnd, ref BottomRight))
                    return;

                RECT Screen = new RECT { Left = TopLeft.X, Top = TopLeft.Y, Right = BottomRight.X, Bottom = BottomRight.Y };
                ClipCursor(ref Screen);
            }

            private void ReleaseCursorClip()
            {
                if (_cursorClipped)
                    ClipCursor(IntPtr.Zero);
            }

            public void SetCursorVisible(bool visible)
            {
                EnsureAlive();

                if (_cursorVisible == visible)
                    return;

                _cursorVisible = visible;
                ApplyCursor();
            }

            private void ApplyCursor()
            {
                SetCursor(_cursorVisible ? LoadCursorW(IntPtr.Zero, IDC_ARROW) : IntPtr.Zero);
            }

            public void Present()
            {
                EnsureAlive();

                _style = _manager.ApplyDecorations(_hwnd, _style, _decorated, _resizable);
                _manager.UpdateWindowText(_hwnd, _title);
                _manager.UpdateWindowSize(_hwnd, _style, _width, _height);

                if (_visible)
                {
                    _manager.UpdateWindowVisibility(_hwnd, true);
                    _manager.UpdateWindowState(_hwnd, _state);
                }
                else
                {
                    _manager.UpdateWindowVisibility(_hwnd, false);
                }
            }

            public IntPtr NativeHandle => _hwnd;

            public void Show() => Visible = true;

            public void Hide() => Visible = false;

            public void Close() => Dispose();

            public void Dispose()
            {
                if (_disposed)
                    return;

                ReleaseCursorClip();
                _layered.Release();
                _cursorClipped = false;
                _disposed = true;
                _hdc = IntPtr.Zero;
                _clip = null;
                _selectedPen = IntPtr.Zero;
                _selectedBrush = IntPtr.Zero;
                _textStateApplied = false;

                // The window leaves the table before DestroyWindow deactivates it, so the loss is read afterwards.
                bool foreground = IsTopLevel && GetForegroundWindow() == _hwnd;
                CloseWindowHandle(_hwnd);

                if (foreground && !_manager.IsHostWindow(GetForegroundWindow()))
                    ReportHostFocusLost();
            }

            private void ReportHostFocusLost()
            {
                HostEventQueue.Enqueue(WM_KILLFOCUS, 0, 0, _guestWindow);
                _manager._hostFocusLost = true;
            }

            internal IntPtr HandleMessage(uint msg, IntPtr wParam, IntPtr lParam)
            {
                switch (msg)
                {
                    case WM_MOUSEMOVE:
                    case WM_LBUTTONDOWN:
                    case WM_LBUTTONUP:
                    case WM_RBUTTONDOWN:
                    case WM_RBUTTONUP:
                    case WM_MBUTTONDOWN:
                    case WM_MBUTTONUP:
                    case WM_XBUTTONDOWN:
                    case WM_XBUTTONUP:
                    {
                        POINT origin = new POINT { X = 0, Y = 0 };
                        if (ClientToScreen(_hwnd, ref origin))
                            HostEventQueue.EnqueuePointer(msg, unchecked((ulong)(long)wParam), unchecked((ulong)(long)lParam), _guestWindow, origin.X, origin.Y);
                        else
                            HostEventQueue.Enqueue(msg, unchecked((ulong)(long)wParam), unchecked((ulong)(long)lParam), _guestWindow);

                        break;
                    }

                    case WM_MOUSEWHEEL:
                    case WM_MOUSEHWHEEL:
                    case WM_KEYDOWN:
                    case WM_KEYUP:
                    case WM_CHAR:
                    case WM_SYSKEYDOWN:
                    case WM_SYSKEYUP:
                        HostEventQueue.Enqueue(msg, unchecked((ulong)(long)wParam), unchecked((ulong)(long)lParam), _guestWindow);
                        break;

                    case WM_INPUT:
                        ForwardRawInput(lParam);
                        break;

                    case WM_ACTIVATE:
                        if ((unchecked((uint)(long)wParam) & 0xFFFF) == WA_INACTIVE)
                        {
                            ReleaseCursorClip();

                            // Activation that leaves Brovan is never an echo, even while a guest request runs.
                            if (!(IsTopLevel && _manager.IsHostWindow(lParam)))
                                ReportHostFocusLost();
                        }
                        else
                        {
                            ApplyCursorClip();

                            // After a real loss, the guest has to hear that the host took it back.
                            if (!EchoesGuest || _manager._hostFocusLost)
                                HostEventQueue.Enqueue(WM_SETFOCUS, 0, 0, _guestWindow);

                            _manager._hostFocusLost = false;
                        }

                        break;

                    // The window class carries no cursor, so the shape the pointer keeps on the way in is the one
                    // it holds until this answers.
                    case WM_SETCURSOR:
                        if ((unchecked((uint)(long)lParam) & 0xFFFF) == HTCLIENT)
                        {
                            ApplyCursor();
                            return new IntPtr(1);
                        }

                        break;

                    case WM_SIZE:
                        TrackHostResize(unchecked((uint)(long)wParam), unchecked((ulong)(long)lParam));
                        ApplyCursorClip();
                        if (!EchoesGuest && !_layeredByUpdate)
                            HostEventQueue.MarkRepaint(_guestWindow);
                        break;

                    case WM_MOVE:
                        ApplyCursorClip();
                        if (!EchoesGuest)
                            HostEventQueue.Enqueue(WM_MOVE, 0, unchecked((ulong)(long)lParam), _guestWindow);
                        break;

                    // No WM_PAINT for an UpdateLayeredWindow surface. The host keeps it.
                    case WM_PAINT:
                    case WM_SHOWWINDOW:
                        if (!_layeredByUpdate)
                            HostEventQueue.MarkRepaint(_guestWindow);
                        break;

                    case WM_DPICHANGED:
                        HostDisplayMetrics.Invalidate();
                        HostEventQueue.MarkDpiChanged(unchecked((uint)(long)wParam) & 0xFFFF);
                        HostEventQueue.MarkRepaint(_guestWindow);
                        return IntPtr.Zero;

                    case WM_CLOSE:
                        HostEventQueue.RequestClose(_guestWindow);
                        return IntPtr.Zero;

                    case WM_DESTROY:
                        _manager.RemoveWindow(_hwnd);
                        if (!IsTopLevel && Windows.IsEmpty)
                            PostQuitMessage(0);

                        return IntPtr.Zero;
                }

                return DefWindowProcW(_hwnd, msg, wParam, lParam);
            }

            private void TrackHostResize(uint sizeType, ulong lParam)
            {
                if (sizeType == SIZE_MAXHIDE || sizeType == SIZE_MAXSHOW)
                    return;

                int width = (int)(lParam & 0xFFFF);
                int height = (int)((lParam >> 16) & 0xFFFF);
                bool iconic = sizeType == SIZE_MINIMIZED || width <= 0 || height <= 0;

                _state = iconic ? WindowState.Minimized
                    : sizeType == SIZE_MAXIMIZED ? WindowState.Maximized
                    : WindowState.Normal;

                if (!iconic)
                {
                    _width = width;
                    _height = height;
                }

                if (!EchoesGuest)
                    HostEventQueue.Enqueue(WM_SIZE, sizeType, lParam, _guestWindow);
            }

            private void EnsureAlive()
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(WindowsWindow));
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASSEXW
        {
            public uint cbSize;
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpszClassName;
            public IntPtr hIconSm;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
            public uint lPrivate;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ClientToScreen(IntPtr hWnd, ref POINT lpPoint);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetCursorPos(int X, int Y);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ClipCursor(ref RECT lpRect);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ClipCursor(IntPtr lpRect);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetCursor(IntPtr hCursor);

        [StructLayout(LayoutKind.Sequential)]
        private struct RAWINPUTDEVICE
        {
            public ushort usUsagePage;
            public ushort usUsage;
            public uint dwFlags;
            public IntPtr hwndTarget;
        }

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RegisterRawInputDevices(ref RAWINPUTDEVICE pRawInputDevices, uint uiNumDevices, uint cbSize);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetRawInputData(IntPtr hRawInput, uint uiCommand, IntPtr pData, ref uint pcbSize, uint cbSizeHeader);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr LoadCursorW(IntPtr hInstance, IntPtr lpCursorName);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr WindowProcDelegate(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateWindowExW(
            int dwExStyle,
            string lpClassName,
            string lpWindowName,
            uint dwStyle,
            int X,
            int Y,
            int nWidth,
            int nHeight,
            IntPtr hWndParent,
            IntPtr hMenu,
            IntPtr hInstance,
            IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetWindowTextW(IntPtr hWnd, string lpString);

        [DllImport("user32.dll", EntryPoint = "DestroyWindow", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyWindowNative(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnableWindow(IntPtr hWnd, [MarshalAs(UnmanagedType.Bool)] bool bEnable);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsZoomed(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetLayeredWindowAttributes(IntPtr hwnd, uint crKey, byte bAlpha, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct BLENDFUNCTION
        {
            public byte BlendOp;
            public byte BlendFlags;
            public byte SourceConstantAlpha;
            public byte AlphaFormat;
        }

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern unsafe bool UpdateLayeredWindow(IntPtr hWnd, IntPtr hdcDst, POINT* pptDst, SIZE* psize, IntPtr hdcSrc,
            POINT* pptSrc, uint crKey, BLENDFUNCTION* pblend, uint dwFlags);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustWindowRectEx(ref RECT lpRect, uint dwStyle, [MarshalAs(UnmanagedType.Bool)] bool bMenu, uint dwExStyle);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustWindowRectExForDpi(ref RECT lpRect, uint dwStyle, [MarshalAs(UnmanagedType.Bool)] bool bMenu, uint dwExStyle, uint dpi);

        [DllImport("user32.dll")]
        private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr dpiContext);

        [DllImport("user32.dll")]
        private static extern uint GetDpiForWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr DispatchMessageW(ref MSG lpmsg);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindowLongPtrW(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowLongPtrW(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern void PostQuitMessage(int nExitCode);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandleW(string lpModuleName);

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref uint pvAttribute, int cbAttribute);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ExtTextOutW(IntPtr hdc, int x, int y, uint fuOptions, ref RECT lprc, string lpString, uint cbCount, IntPtr lpDx);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern int SetTextColor(IntPtr hdc, int crColor);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern int SetBkColor(IntPtr hdc, int crColor);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern int SetBkMode(IntPtr hdc, int iBkMode);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTextExtentPoint32W(IntPtr hdc, string lpString, int cchString, out SIZE psizl);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTextMetricsW(IntPtr hdc, out TEXTMETRICW lptm);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hObject);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr GetStockObject(int fnObject);

        private const int STOCK_OBJECT_WHITE_BRUSH = 0;
        private const int STOCK_OBJECT_BLACK_PEN = 7;
        private const int STOCK_OBJECT_DEFAULT_GUI_FONT = 17;

        private const int TRANSPARENT = 1;
        private const int OPAQUE = 2;
        private const uint ETO_OPAQUE = 0x0002;
        private const uint BI_RGB = 0;
        private const uint DIB_RGB_COLORS = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct BITMAPINFOHEADER
        {
            public uint biSize;
            public int biWidth;
            public int biHeight;
            public ushort biPlanes;
            public ushort biBitCount;
            public uint biCompression;
            public uint biSizeImage;
            public int biXPelsPerMeter;
            public int biYPelsPerMeter;
            public uint biClrUsed;
            public uint biClrImportant;
        }

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreateDIBSection(IntPtr hdc, ref BITMAPINFOHEADER pbmi, uint usage,
            out IntPtr ppvBits, IntPtr hSection, uint offset);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern unsafe int StretchDIBits(IntPtr hdc, int xDest, int yDest, int destWidth, int destHeight,
            int xSrc, int ySrc, int srcWidth, int srcHeight, void* bits, ref BITMAPINFOHEADER bmi, uint usage, uint rop);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool BitBlt(IntPtr hdc, int x, int y, int width, int height, IntPtr hdcSrc, int xSrc, int ySrc, uint rop);

        private const uint SRCCOPY = 0x00CC0020;

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern bool DeleteDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        private static extern bool GdiFlush();

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveToEx(IntPtr hdc, int x, int y, IntPtr lpPoint);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LineTo(IntPtr hdc, int x, int y);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Rectangle(IntPtr hdc, int left, int top, int right, int bottom);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Ellipse(IntPtr hdc, int left, int top, int right, int bottom);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RoundRect(IntPtr hdc, int left, int top, int right, int bottom, int width, int height);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern unsafe bool Polygon(IntPtr hdc, POINT* points, int count);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern unsafe bool Polyline(IntPtr hdc, POINT* points, int count);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreatePen(int fnPenStyle, int nWidth, int crColor);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreateSolidBrush(int crColor);

        private const byte CleartypeQuality = 5;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LOGFONTW
        {
            public int lfHeight;
            public int lfWidth;
            public int lfEscapement;
            public int lfOrientation;
            public int lfWeight;
            public byte lfItalic;
            public byte lfUnderline;
            public byte lfStrikeOut;
            public byte lfCharSet;
            public byte lfOutPrecision;
            public byte lfClipPrecision;
            public byte lfQuality;
            public byte lfPitchAndFamily;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string lfFaceName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ENUMLOGFONTEXW
        {
            public LOGFONTW elfLogFont;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string elfFullName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string elfStyle;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string elfScript;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NEWTEXTMETRICW
        {
            public int tmHeight;
            public int tmAscent;
            public int tmDescent;
            public int tmInternalLeading;
            public int tmExternalLeading;
            public int tmAveCharWidth;
            public int tmMaxCharWidth;
            public int tmWeight;
            public int tmOverhang;
            public int tmDigitizedAspectX;
            public int tmDigitizedAspectY;
            public ushort tmFirstChar;
            public ushort tmLastChar;
            public ushort tmDefaultChar;
            public ushort tmBreakChar;
            public byte tmItalic;
            public byte tmUnderlined;
            public byte tmStruckOut;
            public byte tmPitchAndFamily;
            public byte tmCharSet;
            public uint ntmFlags;
            public uint ntmSizeEM;
            public uint ntmCellHeight;
            public uint ntmAvgWidth;
        }

        private delegate int EnumFontFamExProc(IntPtr logFont, IntPtr textMetric, uint fontType, IntPtr parameter);

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
        private static extern int EnumFontFamiliesExW(IntPtr hdc, ref LOGFONTW logFont, EnumFontFamExProc callback, IntPtr parameter, uint flags);

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFontIndirectW(ref LOGFONTW lplf);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteObject(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct RGNDATAHEADER
        {
            public uint Size;
            public uint Type;
            public uint Count;
            public uint RegionSize;
            public RECT Bound;
        }

        private const uint RDH_RECTANGLES = 1;

        [DllImport("gdi32.dll")]
        private static extern unsafe IntPtr ExtCreateRegion(IntPtr transform, uint count, byte* data);

        [DllImport("gdi32.dll")]
        private static extern int SelectClipRgn(IntPtr hdc, IntPtr region);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PatBlt(IntPtr hdc, int x, int y, int width, int height, uint rop);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern unsafe bool GetKeyboardState(byte* lpKeyState);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern unsafe int ToUnicode(uint wVirtKey, uint wScanCode, byte* lpKeyState, char* pwszBuff, int cchBuff, uint wFlags);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint MsgWaitForMultipleObjectsEx(uint nCount, ref IntPtr pHandles, uint dwMilliseconds, uint dwWakeMask, uint dwFlags);

        private const int PS_SOLID = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct SIZE
        {
            public int cx;
            public int cy;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct TEXTMETRICW
        {
            public int tmHeight;
            public int tmAscent;
            public int tmDescent;
            public int tmInternalLeading;
            public int tmExternalLeading;
            public int tmAveCharWidth;
            public int tmMaxCharWidth;
            public int tmWeight;
            public int tmOverhang;
            public int tmDigitizedAspectX;
            public int tmDigitizedAspectY;
            public ushort tmFirstChar;
            public ushort tmLastChar;
            public ushort tmDefaultChar;
            public ushort tmBreakChar;
            public byte tmItalic;
            public byte tmUnderlined;
            public byte tmStruckOut;
            public byte tmPitchAndFamily;
            public byte tmCharSet;
        }
    }
}
