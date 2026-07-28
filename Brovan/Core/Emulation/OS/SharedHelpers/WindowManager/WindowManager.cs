using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal static class HostEventQueue
    {
        private const uint WM_CLOSE = 0x0010;
        private const uint WM_MOUSEMOVE = 0x0200;
        private const int InitialCapacity = 256;

        private struct HostEvent
        {
            public uint Message;
            public ulong WParam;
            public ulong LParam;
        }

        private static readonly object InputSync = new();
        private static HostEvent[] _input = new HostEvent[InitialCapacity];
        private static int _head;
        private static int _count;

        private static int _pendingRepaint;
        private static int _closeRequested;
        private static int _pendingDpi;

        public static void RequestClose()
        {
            if (Interlocked.Exchange(ref _closeRequested, 1) != 0)
                Environment.Exit(0);

            Enqueue(WM_CLOSE, 0, 0);
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
            }
        }

        public static void MarkDpiChanged(uint dpi)
        {
            Interlocked.Exchange(ref _pendingDpi, (int)dpi);
        }

        public static uint ConsumeDpiChange()
        {
            return (uint)Interlocked.Exchange(ref _pendingDpi, 0);
        }

        public static void MarkRepaint()
        {
            Interlocked.Exchange(ref _pendingRepaint, 1);
        }

        public static bool ConsumeRepaint()
        {
            return Interlocked.Exchange(ref _pendingRepaint, 0) != 0;
        }

        public static void Enqueue(uint message, ulong wParam, ulong lParam)
        {
            lock (InputSync)
            {
                if (message == WM_MOUSEMOVE && _count != 0)
                {
                    ref HostEvent tail = ref _input[(_head + _count - 1) & (_input.Length - 1)];
                    if (tail.Message == WM_MOUSEMOVE)
                    {
                        tail.WParam = wParam;
                        tail.LParam = lParam;
                        return;
                    }
                }

                if (_count == _input.Length)
                    Grow();

                ref HostEvent slot = ref _input[(_head + _count) & (_input.Length - 1)];
                slot.Message = message;
                slot.WParam = wParam;
                slot.LParam = lParam;
                _count++;
            }
        }

        public static bool TryDequeue(out uint message, out ulong wParam, out ulong lParam)
        {
            lock (InputSync)
            {
                if (_count == 0)
                {
                    message = 0;
                    wParam = 0;
                    lParam = 0;
                    return false;
                }

                ref HostEvent slot = ref _input[_head];
                message = slot.Message;
                wParam = slot.WParam;
                lParam = slot.LParam;

                _head = (_head + 1) & (_input.Length - 1);
                _count--;
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
        private const uint MinimumDpi = 48;
        private const uint MaximumDpi = 480;

        private static readonly object Sync = new();
        private static readonly IntPtr PerMonitorAwareV2 = new(-4);

        private static uint _systemDpi;
        private static uint _rawDpi;
        private static int _screenWidth;
        private static int _screenHeight;

        public static bool VirtualizesUnawareWindows => OperatingSystem.IsWindows();

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
        void RenderText(IntPtr windowHandle, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options);
    }

    public enum GdiPrimitiveKind
    {
        Line,
        FillRect,
        Rectangle,
        Ellipse,
        RoundRect,
        Polygon,
        Polyline
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

    public struct GdiPrimitive
    {
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

    public interface ITextMetricsSupport
    {
        bool MeasureText(string text, out int width, out int height);

        bool GetTextMetrics(out TextMetricsData metrics);
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

        IntPtr NativeHandle { get; }

        void Show();

        void Hide();

        void Close();
    }

    public static class WindowManagerFactory
    {
        public static IDisplayConnection Create()
        {
            Func<IDisplayConnection> factory;

            if (OperatingSystem.IsWindows())
                factory = () => new WindowsWinManager();
            else if (OperatingSystem.IsLinux())
                factory = () => new LinuxWinManager();
            else
                throw new PlatformNotSupportedException("No supported window backend is available for this platform.");

            return new GuiThreadManager(factory);
        }
    }
}
