using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal static class HostEventQueue
    {
        private const uint WM_CLOSE = 0x0010;
        private const uint WM_SIZE = 0x0005;
        private const uint WM_MOVE = 0x0003;
        private const uint WM_MOUSEMOVE = 0x0200;
        private const int InitialCapacity = 256;

        // Window is 0 on a single surface backend. A pointer position is relative to the origin.
        internal struct HostEvent
        {
            public uint Message;
            public ulong WParam;
            public ulong LParam;
            public ulong Window;
            public bool HasOrigin;
            public int OriginX;
            public int OriginY;
        }

        private static readonly object InputSync = new();
        private static HostEvent[] _input = new HostEvent[InitialCapacity];
        private static int _head;
        private static int _count;
        private static readonly List<ulong> _repaintWindows = new();
        private static readonly Dictionary<ulong, int> _pendingGeometry = new();

        // Pointer travel reported by the host input device instead of a pointer position. Motion derived from
        // positions cannot survive a warp: the host reports where the pointer ended up, not how it got there.
        internal const uint RawMouseMotion = 0x10000001;

        internal static bool RawMouseAvailable;

        private static int _pendingRepaint;
        private static int _closeRequested;
        private static int _pendingDpi;

        // The GUI thread fills this queue, and DrainHostEvents on the scheduler thread is the only thing that
        // moves it into a guest message queue. Without the bump a scheduler that skips its wakeup scan never
        // reaches DrainHostEvents and host input stops arriving.
        internal static WakeSignal WakeSignal;

        private static void Signal()
        {
            WakeSignal?.Bump();
        }

        public static void RequestClose()
        {
            if (Interlocked.Exchange(ref _closeRequested, 1) != 0)
                Environment.Exit(0);

            Enqueue(WM_CLOSE, 0, 0);
        }

        public static void RequestClose(ulong window)
        {
            if (window == 0)
            {
                RequestClose();
                return;
            }

            Enqueue(WM_CLOSE, 0, 0, window);
        }

        public static void Reset()
        {
            Interlocked.Exchange(ref _closeRequested, 0);
            Interlocked.Exchange(ref _pendingRepaint, 0);
            Interlocked.Exchange(ref _pendingDpi, 0);

            lock (InputSync)
            {
                _head = 0;
                _count = 0;
                _repaintWindows.Clear();
                _pendingGeometry.Clear();
            }
        }

        public static bool GeometryPending => IsGeometryPending(0);

        public static bool IsGeometryPending(ulong window)
        {
            lock (InputSync)
                return _pendingGeometry.ContainsKey(window);
        }

        public static void MarkDpiChanged(uint dpi)
        {
            Interlocked.Exchange(ref _pendingDpi, (int)dpi);
            Signal();
        }

        public static uint ConsumeDpiChange()
        {
            return (uint)Interlocked.Exchange(ref _pendingDpi, 0);
        }

        public static void MarkRepaint()
        {
            Interlocked.Exchange(ref _pendingRepaint, 1);
            Signal();
        }

        public static void MarkRepaint(ulong window)
        {
            if (window == 0)
            {
                MarkRepaint();
                return;
            }

            lock (InputSync)
            {
                if (!_repaintWindows.Contains(window))
                    _repaintWindows.Add(window);
            }

            Signal();
        }

        public static bool ConsumeRepaint()
        {
            return Interlocked.Exchange(ref _pendingRepaint, 0) != 0;
        }

        public static bool TryTakeRepaint(out ulong window)
        {
            lock (InputSync)
            {
                int Last = _repaintWindows.Count - 1;
                if (Last < 0)
                {
                    window = 0;
                    return false;
                }

                window = _repaintWindows[Last];
                _repaintWindows.RemoveAt(Last);
                return true;
            }
        }

        public static void EnqueueRawMouseMotion(int deltaX, int deltaY)
        {
            if (deltaX == 0 && deltaY == 0)
                return;

            lock (InputSync)
            {
                if (_count != 0)
                {
                    ref HostEvent tail = ref _input[(_head + _count - 1) & (_input.Length - 1)];
                    if (tail.Message == RawMouseMotion)
                    {
                        tail.WParam = unchecked((ulong)(long)(unchecked((int)(uint)tail.WParam) + deltaX));
                        tail.LParam = unchecked((ulong)(long)(unchecked((int)(uint)tail.LParam) + deltaY));
                        Signal();
                        return;
                    }
                }

                if (_count == _input.Length)
                    Grow();

                _input[(_head + _count) & (_input.Length - 1)] = new HostEvent
                {
                    Message = RawMouseMotion,
                    WParam = unchecked((ulong)(long)deltaX),
                    LParam = unchecked((ulong)(long)deltaY)
                };
                _count++;
            }

            Signal();
        }

        public static ulong MakeLParam(int low, int high)
        {
            return (ulong)(uint)(((high & 0xFFFF) << 16) | (low & 0xFFFF));
        }

        public static void Enqueue(uint message, ulong wParam, ulong lParam)
        {
            Enqueue(message, wParam, lParam, 0);
        }

        public static void Enqueue(uint message, ulong wParam, ulong lParam, ulong window)
        {
            Enqueue(new HostEvent { Message = message, WParam = wParam, LParam = lParam, Window = window });
        }

        public static void EnqueuePointer(uint message, ulong wParam, ulong lParam, ulong window, int originX, int originY)
        {
            Enqueue(new HostEvent
            {
                Message = message,
                WParam = wParam,
                LParam = lParam,
                Window = window,
                HasOrigin = true,
                OriginX = originX,
                OriginY = originY
            });
        }

        private static void Enqueue(in HostEvent hostEvent)
        {
            uint message = hostEvent.Message;

            lock (InputSync)
            {
                if ((message == WM_MOUSEMOVE || message == WM_SIZE || message == WM_MOVE) && _count != 0)
                {
                    ref HostEvent tail = ref _input[(_head + _count - 1) & (_input.Length - 1)];
                    if (tail.Message == message && tail.Window == hostEvent.Window)
                    {
                        tail = hostEvent;
                        Signal();
                        return;
                    }
                }

                if (_count == _input.Length)
                    Grow();

                _input[(_head + _count) & (_input.Length - 1)] = hostEvent;
                _count++;

                if (message == WM_SIZE || message == WM_MOVE)
                    _pendingGeometry[hostEvent.Window] = _pendingGeometry.GetValueOrDefault(hostEvent.Window) + 1;
            }

            Signal();
        }

        public static bool TryDequeue(out HostEvent hostEvent)
        {
            lock (InputSync)
            {
                if (_count == 0)
                {
                    hostEvent = default;
                    return false;
                }

                hostEvent = _input[_head];

                _head = (_head + 1) & (_input.Length - 1);
                _count--;

                uint message = hostEvent.Message;
                if ((message == WM_SIZE || message == WM_MOVE) && _pendingGeometry.TryGetValue(hostEvent.Window, out int Pending))
                {
                    if (Pending <= 1)
                        _pendingGeometry.Remove(hostEvent.Window);
                    else
                        _pendingGeometry[hostEvent.Window] = Pending - 1;
                }

                return true;
            }
        }

        private static void Grow()
        {
            HostEvent[] grown = new HostEvent[_input.Length * 2];
            int mask = _input.Length - 1;
            for (int i = 0; i < _count; i++)
                grown[i] = _input[(_head + i) & mask];

            _input = grown;
            _head = 0;
        }
    }

    public enum LinuxDisplayBackend
    {
        None,
        X11,
        Wayland
    }

    public enum WindowState
    {
        Normal,
        Minimized,
        Maximized,
        Fullscreen
    }

    public enum DpiAwareness
    {
        Unaware,
        System,
        PerMonitor
    }

    internal static class HostDisplayMetrics
    {
        internal const uint DefaultDpi = 96;

        private const int MonitorDefaultToPrimary = 0x0001;
        private const int MdtEffectiveDpi = 0;
        private const int MdtRawDpi = 2;
        private const int SmCxScreen = 0;
        private const int SmCyScreen = 1;
        private const int FallbackScreenWidth = 1920;
        private const int FallbackScreenHeight = 1080;
        private const int MonitorInfoSize = 40;
        private const int MonitorInfoWorkOffset = 20;
        private const uint MinimumDpi = 48;
        private const uint MaximumDpi = 480;

        private static readonly object Sync = new();
        private static readonly IntPtr PerMonitorAwareV2 = new(-4);
        private static readonly IntPtr SystemAware = new(-2);
        private static readonly IntPtr Unaware = new(-1);

        private static uint _systemDpi;
        private static uint _rawDpi;
        private static int _screenWidth;
        private static int _screenHeight;
        private static int _workLeft;
        private static int _workTop;
        private static int _workRight;
        private static int _workBottom;
        private static IntPtr _pointerDisplay;

        public static bool VirtualizesUnawareWindows => OperatingSystem.IsWindows();

        /// <summary>
        /// Adopts the DPI awareness the host window was created with. Awareness is per thread on Windows, and a
        /// thread that leaves it at the process default reads window rectangles back DPI-virtualized - so a host
        /// API that reports the window's own size (a Vulkan surface's currentExtent, for one) would answer with
        /// scaled pixels that no longer match the window the guest asked for. Returns the previous context to
        /// hand back to <see cref="LeaveWindowDpiContext"/>.
        /// </summary>
        public static IntPtr EnterWindowDpiContext(DpiAwareness Awareness)
        {
            if (!OperatingSystem.IsWindows())
                return IntPtr.Zero;

            IntPtr Context = Awareness switch
            {
                DpiAwareness.PerMonitor => PerMonitorAwareV2,
                DpiAwareness.System => SystemAware,
                _ => Unaware,
            };

            try
            {
                return NativeWinImports.SetThreadDpiAwarenessContext(Context);
            }
            catch
            {
                return IntPtr.Zero;
            }
        }

        public static void LeaveWindowDpiContext(IntPtr Previous)
        {
            if (!OperatingSystem.IsWindows() || Previous == IntPtr.Zero)
                return;

            try
            {
                NativeWinImports.SetThreadDpiAwarenessContext(Previous);
            }
            catch
            {
            }
        }

        public static uint SystemDpi
        {
            get
            {
                Ensure();
                return _systemDpi;
            }
        }

        public static uint RawDpi
        {
            get
            {
                Ensure();
                return _rawDpi;
            }
        }

        public static int ScreenWidth
        {
            get
            {
                Ensure();
                return _screenWidth;
            }
        }

        public static int ScreenHeight
        {
            get
            {
                Ensure();
                return _screenHeight;
            }
        }

        // Physical pixels.
        public static void GetWorkArea(out int left, out int top, out int right, out int bottom)
        {
            Ensure();
            lock (Sync)
            {
                left = _workLeft;
                top = _workTop;
                right = _workRight;
                bottom = _workBottom;
            }
        }

        // Physical pixels. False on a touch-only host.
        public static unsafe bool TryGetCursorPosition(out int x, out int y)
        {
            x = 0;
            y = 0;

            if (Brovan.Android.AndroidHost.IsActive)
                return false;

            if (OperatingSystem.IsLinux())
                return TryQueryX11Pointer(out x, out y);

            if (!OperatingSystem.IsWindows())
                return false;

            // GetPhysicalCursorPos is DPI virtualized too. Only a per-monitor aware thread gets physical pixels.
            int* point = stackalloc int[2];
            IntPtr previous = EnterWindowDpiContext(DpiAwareness.PerMonitor);
            try
            {
                if (!NativeWinImports.GetPhysicalCursorPos(point))
                    return false;
            }
            catch (EntryPointNotFoundException)
            {
                return false;
            }
            finally
            {
                LeaveWindowDpiContext(previous);
            }

            x = point[0];
            y = point[1];
            return true;
        }

        // Own connection. Xlib state is not shared with the GUI thread.
        private static bool TryQueryX11Pointer(out int x, out int y)
        {
            x = 0;
            y = 0;

            lock (Sync)
            {
                try
                {
                    if (_pointerDisplay == IntPtr.Zero)
                        _pointerDisplay = X11.XOpenDisplay(IntPtr.Zero);

                    if (_pointerDisplay == IntPtr.Zero)
                        return false;

                    IntPtr root = X11.XRootWindow(_pointerDisplay, X11.XDefaultScreen(_pointerDisplay));
                    return X11.XQueryPointer(_pointerDisplay, root, out _, out _, out x, out y, out _, out _, out _) != 0;
                }
                catch (DllNotFoundException)
                {
                    return false;
                }
                catch (EntryPointNotFoundException)
                {
                    return false;
                }
            }
        }

        public static void Invalidate()
        {
            lock (Sync)
                _systemDpi = 0;
        }

        private static void Ensure()
        {
            lock (Sync)
            {
                if (_systemDpi != 0)
                    return;

                _systemDpi = DefaultDpi;
                _rawDpi = DefaultDpi;
                _screenWidth = FallbackScreenWidth;
                _screenHeight = FallbackScreenHeight;
                SetWorkAreaToScreen();

                if (Brovan.Android.AndroidHost.IsActive)
                {
                    EnsureFromAndroidSurface();
                    SetWorkAreaToScreen();
                    return;
                }

                if (OperatingSystem.IsLinux())
                {
                    EnsureFromX11();
                    return;
                }

                if (!OperatingSystem.IsWindows())
                    return;

                IntPtr previous = IntPtr.Zero;
                try
                {
                    previous = NativeWinImports.SetThreadDpiAwarenessContext(PerMonitorAwareV2);

                    IntPtr monitor = NativeWinImports.MonitorFromWindow(IntPtr.Zero, MonitorDefaultToPrimary);
                    if (monitor != IntPtr.Zero)
                    {
                        if (NativeWinImports.GetDpiForMonitor(monitor, MdtEffectiveDpi, out uint effectiveDpi, out _) == 0 && effectiveDpi != 0)
                            _systemDpi = effectiveDpi;

                        if (NativeWinImports.GetDpiForMonitor(monitor, MdtRawDpi, out uint rawDpi, out _) == 0 && rawDpi != 0)
                            _rawDpi = rawDpi;
                        else
                            _rawDpi = _systemDpi;
                    }

                    int width = NativeWinImports.GetSystemMetrics(SmCxScreen);
                    int height = NativeWinImports.GetSystemMetrics(SmCyScreen);
                    if (width > 0 && height > 0)
                    {
                        _screenWidth = width;
                        _screenHeight = height;
                    }

                    SetWorkAreaToScreen();
                    if (monitor != IntPtr.Zero)
                        ReadMonitorWorkArea(monitor);
                }
                catch
                {
                }
                finally
                {
                    if (previous != IntPtr.Zero)
                    {
                        try
                        {
                            NativeWinImports.SetThreadDpiAwarenessContext(previous);
                        }
                        catch
                        {
                        }
                    }
                }
            }
        }

        private static void SetWorkAreaToScreen()
        {
            _workLeft = 0;
            _workTop = 0;
            _workRight = _screenWidth;
            _workBottom = _screenHeight;
        }

        private static unsafe void ReadMonitorWorkArea(IntPtr monitor)
        {
            Span<byte> info = stackalloc byte[MonitorInfoSize];
            info.Clear();
            BinaryPrimitives.WriteInt32LittleEndian(info, MonitorInfoSize);

            fixed (byte* buffer = info)
            {
                if (!NativeWinImports.GetMonitorInfoW(monitor, buffer))
                    return;
            }

            int left = BinaryPrimitives.ReadInt32LittleEndian(info.Slice(MonitorInfoWorkOffset));
            int top = BinaryPrimitives.ReadInt32LittleEndian(info.Slice(MonitorInfoWorkOffset + 4));
            int right = BinaryPrimitives.ReadInt32LittleEndian(info.Slice(MonitorInfoWorkOffset + 8));
            int bottom = BinaryPrimitives.ReadInt32LittleEndian(info.Slice(MonitorInfoWorkOffset + 12));
            if (right <= left || bottom <= top)
                return;

            _workLeft = left;
            _workTop = top;
            _workRight = right;
            _workBottom = bottom;
        }

        private static void EnsureFromAndroidSurface()
        {
            int width = Brovan.Android.AndroidHost.Width;
            int height = Brovan.Android.AndroidHost.Height;
            if (width > 0 && height > 0)
            {
                _screenWidth = width;
                _screenHeight = height;
            }

            uint density = (uint)Brovan.Android.AndroidHost.DensityDpi;
            if (density >= MinimumDpi && density <= MaximumDpi)
            {
                _systemDpi = density;
                _rawDpi = density;
            }
        }

        private static void EnsureFromX11()
        {
            IntPtr display = IntPtr.Zero;
            try
            {
                display = X11.XOpenDisplay(IntPtr.Zero);
                if (display == IntPtr.Zero)
                    return;

                int screen = X11.XDefaultScreen(display);
                int width = X11.XDisplayWidth(display, screen);
                int height = X11.XDisplayHeight(display, screen);
                if (width > 0 && height > 0)
                {
                    _screenWidth = width;
                    _screenHeight = height;
                }

                SetWorkAreaToScreen();
                ReadX11WorkArea(display, screen);

                if (TryReadXftDpi(X11.XResourceManagerString(display), out uint dpi))
                {
                    _systemDpi = dpi;
                    _rawDpi = dpi;
                }
            }
            catch (DllNotFoundException)
            {
            }
            catch (EntryPointNotFoundException)
            {
            }
            finally
            {
                if (display != IntPtr.Zero)
                    X11.XCloseDisplay(display);
            }
        }

        // _NET_WORKAREA holds x, y, width and height for each desktop.
        private static void ReadX11WorkArea(IntPtr display, int screen)
        {
            IntPtr atom = X11.XInternAtom(display, "_NET_WORKAREA", 1);
            if (atom == IntPtr.Zero)
                return;

            if (X11.XGetWindowProperty(display, X11.XRootWindow(display, screen), atom, 0, 4, 0, IntPtr.Zero, out _, out int format, out ulong count, out _, out IntPtr data) != 0 || data == IntPtr.Zero)
                return;

            try
            {
                // A format of 32 means an array of long, not of int32, on LP64.
                if (format != 32 || count < 4)
                    return;

                int x = (int)Marshal.ReadIntPtr(data, 0);
                int y = (int)Marshal.ReadIntPtr(data, IntPtr.Size);
                int width = (int)Marshal.ReadIntPtr(data, IntPtr.Size * 2);
                int height = (int)Marshal.ReadIntPtr(data, IntPtr.Size * 3);
                if (width <= 0 || height <= 0)
                    return;

                _workLeft = x;
                _workTop = y;
                _workRight = x + width;
                _workBottom = y + height;
            }
            finally
            {
                X11.XFree(data);
            }
        }

        private static bool TryReadXftDpi(IntPtr resourceString, out uint dpi)
        {
            dpi = 0;
            if (resourceString == IntPtr.Zero)
                return false;

            string resources = Marshal.PtrToStringUTF8(resourceString);
            if (string.IsNullOrEmpty(resources))
                return false;

            foreach (string line in resources.Split('\n'))
            {
                int separator = line.IndexOf(':');
                if (separator < 0 || !line.AsSpan(0, separator).TrimEnd().SequenceEqual("Xft.dpi"))
                    continue;

                if (!uint.TryParse(line.AsSpan(separator + 1).Trim(), out uint parsed))
                    return false;

                if (parsed < MinimumDpi || parsed > MaximumDpi)
                    return false;

                dpi = parsed;
                return true;
            }

            return false;
        }
    }

    public sealed record WindowOptions
    {
        public string Title { get; init; } = string.Empty;
        public string AppId { get; init; } = string.Empty;
        public int Width { get; init; } = 800;
        public int Height { get; init; } = 600;
        public int X { get; init; } = 0;
        public int Y { get; init; } = 0;
        public bool Visible { get; init; } = true;
        public bool Resizable { get; init; } = true;
        public bool Decorated { get; init; } = true;
        public bool Center { get; init; } = false;
        public WindowState State { get; init; } = WindowState.Normal;
        public DpiAwareness DpiAwareness { get; init; } = DpiAwareness.Unaware;
    }

    public struct WindowData
    {
        public string Title;
        public string Class;
        public int Width;
        public int Height;
        public int X;
        public int Y;
        public bool Show;
        public bool Resizable;
        public bool Decorated;
        public bool Center;
        public WindowState State;

        public WindowOptions ToOptions()
        {
            return new WindowOptions
            {
                Title = Title ?? string.Empty,
                AppId = Class ?? string.Empty,
                Width = Width > 0 ? Width : 800,
                Height = Height > 0 ? Height : 600,
                X = X,
                Y = Y,
                Visible = Show,
                Resizable = Resizable,
                Decorated = Decorated,
                Center = Center,
                State = State,
            };
        }
    }

    public interface ITextRenderSupport
    {
        void RenderText(IntPtr windowHandle, ulong hwnd, IntPtr font, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options, GdiClipRect[] clip);
    }

    public enum GdiPrimitiveKind
    {
        Line,
        FillRect,
        Rectangle,
        Ellipse,
        RoundRect,
        Polygon,
        Polyline,
        Blit,
        Copy
    }

    public struct GdiPenDescriptor
    {
        public uint ColorRef;
        public int Width;
    }

    public struct GdiBrushDescriptor
    {
        public uint ColorRef;
    }

    public struct GdiPoint
    {
        public int X;
        public int Y;
    }

    public struct GdiClipRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public struct GdiPrimitive
    {
        public ulong Hwnd;

        public GdiPrimitiveKind Kind;
        public int X1;
        public int Y1;
        public int X2;
        public int Y2;
        public uint Rop;
        public int RoundedWidth;
        public int RoundedHeight;
        public GdiPoint[] Points;
        public GdiPenDescriptor Pen;
        public GdiBrushDescriptor Brush;
        public bool HasPen;
        public bool HasBrush;

        // Blit only. Top-down 32 bit rows, stretched onto the destination rectangle.
        public uint[] Pixels;
        public bool PixelsPooled;
        public int SourceWidth;
        public int SourceHeight;

        // Copy only. Read from the same surface as it was before the copy.
        public int SourceX;
        public int SourceY;

        // Null draws anywhere, empty draws nothing. Shared and never changed once built.
        public GdiClipRect[] Clip;
    }

    public interface IGdiRenderSupport
    {
        void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive);
    }

    public interface IKeyboardTranslateSupport
    {
        bool TranslateVirtualKey(uint virtualKey, uint scanCode, out char character);
    }

    public struct TextMetricsData
    {
        public int Height;
        public int Ascent;
        public int Descent;
        public int InternalLeading;
        public int ExternalLeading;
        public int AveCharWidth;
        public int MaxCharWidth;
        public int Weight;
        public int Overhang;
        public int DigitizedAspectX;
        public int DigitizedAspectY;
        public ushort FirstChar;
        public ushort LastChar;
        public ushort DefaultChar;
        public ushort BreakChar;
        public byte Italic;
        public byte Underlined;
        public byte StruckOut;
        public byte PitchAndFamily;
        public byte CharSet;
    }

    public readonly record struct FontDescription(
        int Height,
        int Width,
        int Weight,
        bool Italic,
        bool Underline,
        bool StrikeOut,
        byte CharSet,
        byte PitchAndFamily,
        string FaceName);

    public sealed class FontFamilyData
    {
        public string FaceName;
        public string FullName;
        public string Style;
        public byte CharSet;
        public byte PitchAndFamily;
        public int Weight;
        public bool Italic;

        // RASTER_FONTTYPE, DEVICE_FONTTYPE, TRUETYPE_FONTTYPE.
        public uint FontType;

        public TextMetricsData Metrics;
        public uint NtmFlags;
        public uint SizeEm;
        public uint CellHeight;
        public uint AvgWidth;
    }

    public static class HostColor
    {
        // A COLORREF is 0x00BBGGRR, a 32 bit DIB pixel is 0x00RRGGBB.
        public static uint FromColorRef(uint colorRef)
            => ((colorRef & 0x000000FF) << 16) | (colorRef & 0x0000FF00) | ((colorRef & 0x00FF0000) >> 16);
    }

    public interface ITextMetricsSupport
    {
        // A zero font is the host's own default.
        bool MeasureText(IntPtr font, string text, out int width, out int height);

        bool GetTextMetrics(IntPtr font, out TextMetricsData metrics);

        // The buffer is top-down 32 bit, the colours are COLORREF.
        bool RasterizeText(IntPtr font, string text, Span<uint> pixels, int width, int height,
            int x, int y, uint textColor, uint backColor, bool opaque);

        IntPtr CreateFont(in FontDescription description);

        void DeleteFont(IntPtr font);

        // No face name asks for every face, a face name for that family's styles.
        IReadOnlyList<FontFamilyData> EnumerateFontFamilies(string faceName, byte charSet);
    }

    public interface IDisplayConnection : IDisposable
    {
        IWindow CreateWindow(WindowOptions options);

        void PumpEvents();

        /// <summary>
        /// Blocks the calling thread until the host has an event to dispatch, <see cref="Wake"/> is called,
        /// or the timeout elapses. Polling the backend on a fixed interval instead would floor input latency
        /// at the poll period, so the wait has to be armed on both the host event source and the wake object.
        /// </summary>
        void WaitForEvents(int timeoutMilliseconds);

        void Wake();

        bool IsConnected { get; }

        IntPtr NativeHandle { get; }
    }

    public interface IWindow : IDisposable
    {
        string Title { get; set; }

        int Width { get; set; }

        int Height { get; set; }

        bool Visible { get; set; }

        WindowState State { get; set; }

        bool Resizable { get; }

        bool Decorated { get; set; }

        void Present();

        void WarpCursor(int clientX, int clientY);

        void SetCursorClip(bool enabled, int clientLeft, int clientTop, int clientRight, int clientBottom);

        void SetCursorVisible(bool visible);

        IntPtr NativeHandle { get; }

        void Show();

        void Hide();

        void Close();
    }

    /// <summary>
    /// The client rectangle is in guest screen coordinates. The host window takes the guest's DPI awareness, so
    /// these are host screen coordinates too.
    /// </summary>
    public struct TopLevelFrame
    {
        public ulong Window;
        public ulong Owner;
        public string Title;
        public int ClientX;
        public int ClientY;
        public int ClientWidth;
        public int ClientHeight;
        public uint Style;
        public uint ExStyle;
        public bool Visible;
        public bool Enabled;
        public WindowState State;
        public DpiAwareness DpiAwareness;

        public bool LayeredByAttributes;
        public uint LayeredFlags;
        public uint LayeredColorKey;
        public byte LayeredAlpha;

        public bool HostGeometryStale;

        public bool Matches(in TopLevelFrame other)
        {
            return Owner == other.Owner
                && ClientX == other.ClientX
                && ClientY == other.ClientY
                && ClientWidth == other.ClientWidth
                && ClientHeight == other.ClientHeight
                && Style == other.Style
                && ExStyle == other.ExStyle
                && Visible == other.Visible
                && Enabled == other.Enabled
                && State == other.State
                && DpiAwareness == other.DpiAwareness
                && LayeredByAttributes == other.LayeredByAttributes
                && LayeredFlags == other.LayeredFlags
                && LayeredColorKey == other.LayeredColorKey
                && LayeredAlpha == other.LayeredAlpha
                && string.Equals(Title, other.Title, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Pixels is the dirty block as premultiplied top-down 32 bit rows, or null when only position or blend changes.
    /// </summary>
    public sealed class LayeredUpdate
    {
        public int X;
        public int Y;
        public int Width;
        public int Height;
        public uint[] Pixels;
        public bool PixelsPooled;
        public int DirtyLeft;
        public int DirtyTop;
        public int DirtyWidth;
        public int DirtyHeight;
        public uint ColorKey;
        public byte ConstantAlpha;
        public byte AlphaFormat;
        public uint Flags;
    }

    public interface ITopLevelWindow : IWindow
    {
        void SetFrame(uint style, uint exStyle);

        void SetOwner(ITopLevelWindow owner);

        void SetClientBounds(int x, int y, int width, int height);

        void SetEnabled(bool enabled);

        void SetShown(bool shown);

        void Activate();

        void SetLayeredAttributes(uint colorKey, byte alpha, uint flags);

        void UpdateLayered(LayeredUpdate update);
    }

    public interface ITopLevelWindowHost
    {
        ITopLevelWindow CreateTopLevel(in TopLevelFrame frame, ITopLevelWindow owner);

        void Restack(ReadOnlySpan<ITopLevelWindow> topToBottom);
    }

    public static class WindowManagerFactory
    {
        public static IDisplayConnection Create()
        {
            Func<IDisplayConnection> factory;

            if (Brovan.Android.AndroidHost.IsActive)
                factory = () => new Brovan.Android.AndroidWinManager();
            else if (OperatingSystem.IsWindows())
                factory = () => new WindowsWinManager();
            else if (OperatingSystem.IsLinux())
                factory = () => new LinuxWinManager();
            else
                throw new PlatformNotSupportedException("No supported window backend is available for this platform.");

            return new GuiThreadManager(factory);
        }
    }
}
