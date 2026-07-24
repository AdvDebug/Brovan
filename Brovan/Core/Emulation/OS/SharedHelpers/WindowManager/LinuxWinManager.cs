using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public static partial class X11
    {
        [LibraryImport("libX11.so.6")]
        public static partial int XInitThreads();

        [LibraryImport("libX11.so.6")]
        public static unsafe partial IntPtr XSetErrorHandler(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, int> handler);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XOpenDisplay(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial int XDefaultScreen(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XRootWindow(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial int XDisplayWidth(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial int XDisplayHeight(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial nuint XWhitePixel(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial nuint XBlackPixel(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XDefaultColormap(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XCreateSimpleWindow(
            IntPtr display,
            IntPtr parent,
            int x,
            int y,
            uint width,
            uint height,
            uint borderWidth,
            nuint border,
            nuint background);

        [LibraryImport("libX11.so.6")]
        public static partial int XMapWindow(IntPtr display, IntPtr window);

        [LibraryImport("libX11.so.6")]
        public static partial int XUnmapWindow(IntPtr display, IntPtr window);

        [LibraryImport("libX11.so.6")]
        public static partial int XDestroyWindow(IntPtr display, IntPtr window);

        [LibraryImport("libX11.so.6")]
        public static partial int XIconifyWindow(IntPtr display, IntPtr window, int screen);

        [LibraryImport("libX11.so.6", StringMarshalling = StringMarshalling.Utf8)]
        public static partial int XStoreName(IntPtr display, IntPtr window, string windowName);

        [LibraryImport("libX11.so.6")]
        public static partial int XResizeWindow(IntPtr display, IntPtr window, uint width, uint height);

        [LibraryImport("libX11.so.6")]
        public static partial int XMoveWindow(IntPtr display, IntPtr window, int x, int y);

        [LibraryImport("libX11.so.6")]
        public static partial int XSelectInput(IntPtr display, IntPtr window, long eventMask);

        [LibraryImport("libX11.so.6")]
        public static partial int XPending(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial int XNextEvent(IntPtr display, out XEvent @event);

        [LibraryImport("libX11.so.6")]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int XSendEvent(
            IntPtr display,
            IntPtr window,
            [MarshalAs(UnmanagedType.I4)] int propagate,
            long eventMask,
            ref XEvent @event);

        [LibraryImport("libX11.so.6")]
        public static partial int XFlush(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial int XSync(IntPtr display, [MarshalAs(UnmanagedType.I4)] int discard);

        [LibraryImport("libX11.so.6")]
        public static partial int XCloseDisplay(IntPtr display);

        [LibraryImport("libX11.so.6", StringMarshalling = StringMarshalling.Utf8)]
        public static partial IntPtr XInternAtom(IntPtr display, string atomName, [MarshalAs(UnmanagedType.I4)] int onlyIfExists);

        [LibraryImport("libX11.so.6")]
        public static partial int XSetWMProtocols(IntPtr display, IntPtr window, IntPtr[] protocols, int count);

        [LibraryImport("libX11.so.6")]
        public static partial int XChangeProperty(
            IntPtr display,
            IntPtr window,
            IntPtr property,
            IntPtr type,
            int format,
            int mode,
            IntPtr data,
            int elementCount);

        [LibraryImport("libX11.so.6")]
        public static partial int XDeleteProperty(IntPtr display, IntPtr window, IntPtr property);

        [LibraryImport("libX11.so.6")]
        public static partial void XSetWMNormalHints(IntPtr display, IntPtr window, ref XSizeHints hints);

        [LibraryImport("libX11.so.6")]
        public static unsafe partial int XLookupString(XEvent* @event, byte* buffer, int bytes, out IntPtr keysym, IntPtr status);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XkbKeycodeToKeysym(IntPtr display, byte keycode, int group, int level);

        [LibraryImport("libX11.so.6")]
        [return: MarshalAs(UnmanagedType.I4)]
        public static partial int XkbSetDetectableAutoRepeat(IntPtr display, [MarshalAs(UnmanagedType.I4)] int detectable, out int supported);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XCreateGC(IntPtr display, IntPtr drawable, nuint valuemask, IntPtr values);

        [LibraryImport("libX11.so.6")]
        public static partial int XFreeGC(IntPtr display, IntPtr gc);

        [LibraryImport("libX11.so.6")]
        public static partial int XSetForeground(IntPtr display, IntPtr gc, nuint foreground);

        [LibraryImport("libX11.so.6")]
        public static partial int XSetBackground(IntPtr display, IntPtr gc, nuint background);

        [LibraryImport("libX11.so.6")]
        public static partial int XSetFunction(IntPtr display, IntPtr gc, int function);

        [LibraryImport("libX11.so.6")]
        public static partial int XSetLineAttributes(IntPtr display, IntPtr gc, uint lineWidth, int lineStyle, int capStyle, int joinStyle);

        [LibraryImport("libX11.so.6")]
        public static partial int XSetFont(IntPtr display, IntPtr gc, IntPtr font);

        [LibraryImport("libX11.so.6")]
        public static partial int XAllocColor(IntPtr display, IntPtr colormap, ref XColor color);

        [LibraryImport("libX11.so.6")]
        public static partial int XDrawLine(IntPtr display, IntPtr drawable, IntPtr gc, int x1, int y1, int x2, int y2);

        [LibraryImport("libX11.so.6")]
        public static partial int XDrawLines(IntPtr display, IntPtr drawable, IntPtr gc, XPoint[] points, int count, int mode);

        [LibraryImport("libX11.so.6")]
        public static partial int XDrawRectangle(IntPtr display, IntPtr drawable, IntPtr gc, int x, int y, uint width, uint height);

        [LibraryImport("libX11.so.6")]
        public static partial int XFillRectangle(IntPtr display, IntPtr drawable, IntPtr gc, int x, int y, uint width, uint height);

        [LibraryImport("libX11.so.6")]
        public static partial int XDrawArc(IntPtr display, IntPtr drawable, IntPtr gc, int x, int y, uint width, uint height, int angle1, int angle2);

        [LibraryImport("libX11.so.6")]
        public static partial int XFillArc(IntPtr display, IntPtr drawable, IntPtr gc, int x, int y, uint width, uint height, int angle1, int angle2);

        [LibraryImport("libX11.so.6")]
        public static partial int XFillPolygon(IntPtr display, IntPtr drawable, IntPtr gc, XPoint[] points, int count, int shape, int mode);

        [LibraryImport("libX11.so.6", StringMarshalling = StringMarshalling.Utf8)]
        public static partial IntPtr XLoadQueryFont(IntPtr display, string name);

        [LibraryImport("libX11.so.6", StringMarshalling = StringMarshalling.Utf8)]
        public static partial int XDrawString(IntPtr display, IntPtr drawable, IntPtr gc, int x, int y, string str, int length);

        [LibraryImport("libX11.so.6", StringMarshalling = StringMarshalling.Utf8)]
        public static partial int XTextWidth(IntPtr font_struct, string str, int length);

        [LibraryImport("libX11.so.6")]
        public static partial int XFreeFont(IntPtr display, IntPtr font_struct);

        public const int KeyPress = 2;
        public const int KeyRelease = 3;
        public const int ButtonPress = 4;
        public const int ButtonRelease = 5;
        public const int MotionNotify = 6;
        public const int FocusIn = 9;
        public const int FocusOut = 10;
        public const int Expose = 12;
        public const int ConfigureNotify = 22;
        public const int ClientMessage = 33;

        public const long KeyPressMask = 1L << 0;
        public const long KeyReleaseMask = 1L << 1;
        public const long ButtonPressMask = 1L << 2;
        public const long ButtonReleaseMask = 1L << 3;
        public const long PointerMotionMask = 1L << 6;
        public const long ExposureMask = 1L << 15;
        public const long StructureNotifyMask = 1L << 17;
        public const long SubstructureNotifyMask = 1L << 19;
        public const long SubstructureRedirectMask = 1L << 20;
        public const long FocusChangeMask = 1L << 21;

        public const uint ShiftMask = 1 << 0;
        public const uint ControlMask = 1 << 2;
        public const uint Mod1Mask = 1 << 3;
        public const uint Button1Mask = 1 << 8;
        public const uint Button2Mask = 1 << 9;
        public const uint Button3Mask = 1 << 10;

        public const int PropModeReplace = 0;
        public const int XA_STRING = 31;
        public const int XA_WM_CLASS = 67;

        public const int GXcopy = 3;
        public const int GXxor = 6;
        public const int GXinvert = 10;

        public const int LineSolid = 0;
        public const int CapButt = 1;
        public const int JoinMiter = 0;

        public const int CoordModeOrigin = 0;
        public const int Complex = 0;

        [StructLayout(LayoutKind.Sequential, Size = 192)]
        public struct XEvent
        {
            public int Type;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct XKeyEvent
        {
            [FieldOffset(0)] public int Type;
            [FieldOffset(24)] public IntPtr Display;
            [FieldOffset(32)] public IntPtr Window;
            [FieldOffset(64)] public int X;
            [FieldOffset(68)] public int Y;
            [FieldOffset(72)] public int XRoot;
            [FieldOffset(76)] public int YRoot;
            [FieldOffset(80)] public uint State;
            [FieldOffset(84)] public uint Keycode;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct XButtonEvent
        {
            [FieldOffset(0)] public int Type;
            [FieldOffset(64)] public int X;
            [FieldOffset(68)] public int Y;
            [FieldOffset(72)] public int XRoot;
            [FieldOffset(76)] public int YRoot;
            [FieldOffset(80)] public uint State;
            [FieldOffset(84)] public uint Button;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct XMotionEvent
        {
            [FieldOffset(0)] public int Type;
            [FieldOffset(64)] public int X;
            [FieldOffset(68)] public int Y;
            [FieldOffset(72)] public int XRoot;
            [FieldOffset(76)] public int YRoot;
            [FieldOffset(80)] public uint State;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct XConfigureEvent
        {
            [FieldOffset(0)] public int Type;
            [FieldOffset(40)] public IntPtr Window;
            [FieldOffset(48)] public int X;
            [FieldOffset(52)] public int Y;
            [FieldOffset(56)] public int Width;
            [FieldOffset(60)] public int Height;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct XClientMessageEvent
        {
            [FieldOffset(0)] public int Type;
            [FieldOffset(32)] public IntPtr Window;
            [FieldOffset(40)] public IntPtr MessageType;
            [FieldOffset(48)] public int Format;
            [FieldOffset(56)] public IntPtr Data0;
            [FieldOffset(64)] public IntPtr Data1;
            [FieldOffset(72)] public IntPtr Data2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct XColor
        {
            public nuint Pixel;
            public ushort Red;
            public ushort Green;
            public ushort Blue;
            public byte Flags;
            public byte Pad;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct XPoint
        {
            public short X;
            public short Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct XSizeHints
        {
            public nint Flags;
            public int X;
            public int Y;
            public int Width;
            public int Height;
            public int MinWidth;
            public int MinHeight;
            public int MaxWidth;
            public int MaxHeight;
            public int WidthInc;
            public int HeightInc;
            public int MinAspectX;
            public int MinAspectY;
            public int MaxAspectX;
            public int MaxAspectY;
            public int BaseWidth;
            public int BaseHeight;
            public int WinGravity;
        }

        public const int PMinSize = 1 << 4;
        public const int PMaxSize = 1 << 5;

        [StructLayout(LayoutKind.Explicit)]
        public struct XFontStruct
        {
            [FieldOffset(8)] public IntPtr Fid;
            [FieldOffset(20)] public uint MinCharOrByte2;
            [FieldOffset(24)] public uint MaxCharOrByte2;
            [FieldOffset(40)] public uint DefaultChar;
            [FieldOffset(72)] public short MaxWidth;
            [FieldOffset(88)] public int Ascent;
            [FieldOffset(92)] public int Descent;
        }
    }

    public static partial class Wayland
    {
        [LibraryImport("libwayland-client.so.0")]
        public static partial IntPtr wl_display_connect(IntPtr name);

        [LibraryImport("libwayland-client.so.0")]
        public static partial void wl_display_disconnect(IntPtr display);
    }

    internal sealed class LinuxWinManager : IDisplayConnection, ITextRenderSupport, ITextMetricsSupport, IGdiRenderSupport, IKeyboardTranslateSupport
    {
        private const uint WM_SIZE = 0x0005;
        private const uint WM_SETFOCUS = 0x0007;
        private const uint WM_KILLFOCUS = 0x0008;
        private const uint WM_KEYDOWN = 0x0100;
        private const uint WM_KEYUP = 0x0101;
        private const uint WM_SYSKEYDOWN = 0x0104;
        private const uint WM_SYSKEYUP = 0x0105;
        private const uint WM_MOUSEMOVE = 0x0200;
        private const uint WM_LBUTTONDOWN = 0x0201;
        private const uint WM_LBUTTONUP = 0x0202;
        private const uint WM_RBUTTONDOWN = 0x0204;
        private const uint WM_RBUTTONUP = 0x0205;
        private const uint WM_MBUTTONDOWN = 0x0207;
        private const uint WM_MBUTTONUP = 0x0208;
        private const uint WM_MOUSEWHEEL = 0x020A;
        private const uint WM_XBUTTONDOWN = 0x020B;
        private const uint WM_XBUTTONUP = 0x020C;

        private const uint MK_LBUTTON = 0x0001;
        private const uint MK_RBUTTON = 0x0002;
        private const uint MK_SHIFT = 0x0004;
        private const uint MK_CONTROL = 0x0008;
        private const uint MK_MBUTTON = 0x0010;

        private const uint VK_MENU = 0x12;
        private const uint VK_F10 = 0x79;

        private const uint PATCOPY = 0x00F00021;
        private const uint BLACKNESS = 0x00000042;
        private const uint WHITENESS = 0x00FF0062;
        private const uint DSTINVERT = 0x00550009;
        private const uint PATINVERT = 0x005A0049;

        private const long WindowEventMask =
            X11.KeyPressMask | X11.KeyReleaseMask |
            X11.ButtonPressMask | X11.ButtonReleaseMask |
            X11.PointerMotionMask | X11.ExposureMask |
            X11.StructureNotifyMask | X11.FocusChangeMask;

        private readonly object _sync = new();
        private readonly Dictionary<IntPtr, LinuxWindow> _windows = new();
        private readonly Dictionary<uint, nuint> _pixelCache = new();
        private IntPtr _xDisplay;
        private IntPtr _wlDisplay;
        private int _screen;
        private IntPtr _colormap;
        private IntPtr _gc;
        private IntPtr _fontStruct;
        private nuint _whitePixel;
        private nuint _blackPixel;
        private uint _modifierState;
        private bool _disposed;

        private IntPtr _wmProtocols;
        private IntPtr _wmDeleteWindow;
        private IntPtr _netWmName;
        private IntPtr _netWmState;
        private IntPtr _netWmStateFullscreen;
        private IntPtr _netWmStateMaximizedVert;
        private IntPtr _netWmStateMaximizedHorz;
        private IntPtr _motifWmHints;
        private IntPtr _utf8String;

        /// <summary>
        /// Xlib aborts the process from its default error handler. Guest code and the Vulkan ICD both
        /// drive this display, so a stale drawable from a race must degrade rather than kill the emulator.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
        private static int SwallowXError(IntPtr display, IntPtr errorEvent)
        {
            return 0;
        }

        public unsafe LinuxWinManager()
        {
            if (!GeneralHelper.IsLinux)
                throw new PlatformNotSupportedException("Linux window manager needs to be used on a Linux system.");

            X11.XInitThreads();
            X11.XSetErrorHandler(&SwallowXError);

            _xDisplay = X11.XOpenDisplay(IntPtr.Zero);
            if (_xDisplay != IntPtr.Zero)
            {
                InitializeX11();
                return;
            }

            _wlDisplay = Wayland.wl_display_connect(IntPtr.Zero);
            if (_wlDisplay != IntPtr.Zero)
            {
                Wayland.wl_display_disconnect(_wlDisplay);
                _wlDisplay = IntPtr.Zero;
                throw new PlatformNotSupportedException(
                    "Connected to a Wayland compositor, but Brovan renders through X11. Install XWayland or run an X11 session.");
            }

            string supported = string.Join(", ", Enum.GetValues<LinuxDisplayBackend>().Where(x => x != LinuxDisplayBackend.None));
            throw new PlatformNotSupportedException($"No supported Linux display backend was found. Supported desktop environments: {supported}");
        }

        private void InitializeX11()
        {
            _screen = X11.XDefaultScreen(_xDisplay);
            _colormap = X11.XDefaultColormap(_xDisplay, _screen);
            _whitePixel = X11.XWhitePixel(_xDisplay, _screen);
            _blackPixel = X11.XBlackPixel(_xDisplay, _screen);

            _wmProtocols = X11.XInternAtom(_xDisplay, "WM_PROTOCOLS", 0);
            _wmDeleteWindow = X11.XInternAtom(_xDisplay, "WM_DELETE_WINDOW", 0);
            _netWmName = X11.XInternAtom(_xDisplay, "_NET_WM_NAME", 0);
            _netWmState = X11.XInternAtom(_xDisplay, "_NET_WM_STATE", 0);
            _netWmStateFullscreen = X11.XInternAtom(_xDisplay, "_NET_WM_STATE_FULLSCREEN", 0);
            _netWmStateMaximizedVert = X11.XInternAtom(_xDisplay, "_NET_WM_STATE_MAXIMIZED_VERT", 0);
            _netWmStateMaximizedHorz = X11.XInternAtom(_xDisplay, "_NET_WM_STATE_MAXIMIZED_HORZ", 0);
            _motifWmHints = X11.XInternAtom(_xDisplay, "_MOTIF_WM_HINTS", 0);
            _utf8String = X11.XInternAtom(_xDisplay, "UTF8_STRING", 0);

            X11.XkbSetDetectableAutoRepeat(_xDisplay, 1, out _);

            _fontStruct = X11.XLoadQueryFont(_xDisplay, "fixed");
        }

        public bool IsConnected => !_disposed && _xDisplay != IntPtr.Zero;

        public IntPtr NativeHandle => _xDisplay;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(LinuxWinManager));

            options ??= new WindowOptions();

            if (_xDisplay == IntPtr.Zero)
                throw new PlatformNotSupportedException("A live X11 display connection is required for host window creation in the current Linux backend.");

            IntPtr windowHandle = CreateX11Window(options);
            LinuxWindow window = new(this, _xDisplay, windowHandle, options);
            lock (_sync)
                _windows[windowHandle] = window;

            ApplyDecorations(windowHandle, options.Decorated);
            ApplySizeHints(windowHandle, options.Resizable, Math.Max(options.Width, 1), Math.Max(options.Height, 1));
            ApplyState(windowHandle, options.State);
            return window;
        }

        public void PumpEvents()
        {
            if (_disposed || _xDisplay == IntPtr.Zero)
                return;

            while (X11.XPending(_xDisplay) > 0)
            {
                if (X11.XNextEvent(_xDisplay, out X11.XEvent nativeEvent) != 0)
                    break;

                TranslateEvent(ref nativeEvent);
            }

            X11.XFlush(_xDisplay);
        }

        private unsafe void TranslateEvent(ref X11.XEvent nativeEvent)
        {
            switch (nativeEvent.Type)
            {
                case X11.KeyPress:
                case X11.KeyRelease:
                    {
                        ref X11.XKeyEvent key = ref Unsafe.As<X11.XEvent, X11.XKeyEvent>(ref nativeEvent);
                        _modifierState = key.State;

                        uint virtualKey = KeysymToVirtualKey(LookupKeysym((byte)key.Keycode));
                        if (virtualKey == 0)
                            return;

                        bool down = nativeEvent.Type == X11.KeyPress;
                        bool altHeld = (key.State & X11.Mod1Mask) != 0;
                        bool system = altHeld || virtualKey == VK_MENU || virtualKey == VK_F10;

                        uint message = down
                            ? (system ? WM_SYSKEYDOWN : WM_KEYDOWN)
                            : (system ? WM_SYSKEYUP : WM_KEYUP);

                        HostEventQueue.Enqueue(message, virtualKey, BuildKeyLParam(key.Keycode, virtualKey, down, altHeld));
                        return;
                    }

                case X11.ButtonPress:
                case X11.ButtonRelease:
                    {
                        ref X11.XButtonEvent button = ref Unsafe.As<X11.XEvent, X11.XButtonEvent>(ref nativeEvent);
                        _modifierState = button.State;
                        TranslateButton(ref button, nativeEvent.Type == X11.ButtonPress);
                        return;
                    }

                case X11.MotionNotify:
                    {
                        ref X11.XMotionEvent motion = ref Unsafe.As<X11.XEvent, X11.XMotionEvent>(ref nativeEvent);
                        _modifierState = motion.State;
                        HostEventQueue.Enqueue(WM_MOUSEMOVE, StateToMouseKeys(motion.State), MakeLParam(motion.X, motion.Y));
                        return;
                    }

                case X11.Expose:
                    HostEventQueue.MarkRepaint();
                    return;

                case X11.ConfigureNotify:
                    {
                        ref X11.XConfigureEvent configure = ref Unsafe.As<X11.XEvent, X11.XConfigureEvent>(ref nativeEvent);
                        if (TryGetWindow(configure.Window, out LinuxWindow? window))
                            window?.OnConfigured(configure.Width, configure.Height);

                        HostEventQueue.Enqueue(WM_SIZE, 0, MakeLParam(configure.Width, configure.Height));
                        HostEventQueue.MarkRepaint();
                        return;
                    }

                case X11.FocusIn:
                    HostEventQueue.Enqueue(WM_SETFOCUS, 0, 0);
                    return;

                case X11.FocusOut:
                    HostEventQueue.Enqueue(WM_KILLFOCUS, 0, 0);
                    return;

                case X11.ClientMessage:
                    {
                        ref X11.XClientMessageEvent client = ref Unsafe.As<X11.XEvent, X11.XClientMessageEvent>(ref nativeEvent);
                        if (client.MessageType == _wmProtocols && client.Data0 == _wmDeleteWindow)
                            HostEventQueue.RequestClose();

                        return;
                    }
            }
        }

        private void TranslateButton(ref X11.XButtonEvent button, bool pressed)
        {
            uint keys = StateToMouseKeys(button.State);
            ulong position = MakeLParam(button.X, button.Y);

            switch (button.Button)
            {
                case 1:
                    HostEventQueue.Enqueue(pressed ? WM_LBUTTONDOWN : WM_LBUTTONUP, keys, position);
                    return;
                case 2:
                    HostEventQueue.Enqueue(pressed ? WM_MBUTTONDOWN : WM_MBUTTONUP, keys, position);
                    return;
                case 3:
                    HostEventQueue.Enqueue(pressed ? WM_RBUTTONDOWN : WM_RBUTTONUP, keys, position);
                    return;

                case 4:
                case 5:
                    // X delivers wheel notches as press/release pairs; Win32 has a single wheel message.
                    if (!pressed)
                        return;

                    short delta = button.Button == 4 ? (short)120 : (short)-120;
                    HostEventQueue.Enqueue(WM_MOUSEWHEEL, keys | ((ulong)(ushort)delta << 16), MakeLParam(button.XRoot, button.YRoot));
                    return;

                case 8:
                case 9:
                    uint xbutton = button.Button == 8 ? 1u : 2u;
                    HostEventQueue.Enqueue(pressed ? WM_XBUTTONDOWN : WM_XBUTTONUP, keys | ((ulong)xbutton << 16), position);
                    return;
            }
        }

        private static ulong MakeLParam(int low, int high)
        {
            return (ulong)(uint)(((high & 0xFFFF) << 16) | (low & 0xFFFF));
        }

        private static uint StateToMouseKeys(uint state)
        {
            uint keys = 0;
            if ((state & X11.Button1Mask) != 0)
                keys |= MK_LBUTTON;
            if ((state & X11.Button2Mask) != 0)
                keys |= MK_MBUTTON;
            if ((state & X11.Button3Mask) != 0)
                keys |= MK_RBUTTON;
            if ((state & X11.ShiftMask) != 0)
                keys |= MK_SHIFT;
            if ((state & X11.ControlMask) != 0)
                keys |= MK_CONTROL;

            return keys;
        }

        private static ulong BuildKeyLParam(uint keycode, uint virtualKey, bool down, bool altHeld)
        {
            ulong lParam = 1;
            lParam |= (ulong)(keycode & 0xFF) << 16;

            if (IsExtendedKey(virtualKey))
                lParam |= 1UL << 24;

            if (altHeld)
                lParam |= 1UL << 29;

            if (!down)
                lParam |= (1UL << 30) | (1UL << 31);

            return lParam;
        }

        private static bool IsExtendedKey(uint virtualKey)
        {
            switch (virtualKey)
            {
                case 0x21: // VK_PRIOR
                case 0x22: // VK_NEXT
                case 0x23: // VK_END
                case 0x24: // VK_HOME
                case 0x25: // VK_LEFT
                case 0x26: // VK_UP
                case 0x27: // VK_RIGHT
                case 0x28: // VK_DOWN
                case 0x2C: // VK_SNAPSHOT
                case 0x2D: // VK_INSERT
                case 0x2E: // VK_DELETE
                case 0x6F: // VK_DIVIDE
                case 0x90: // VK_NUMLOCK
                case 0xA3: // VK_RCONTROL
                case 0xA5: // VK_RMENU
                    return true;
                default:
                    return false;
            }
        }

        private IntPtr LookupKeysym(byte keycode)
        {
            return X11.XkbKeycodeToKeysym(_xDisplay, keycode, 0, 0);
        }

        private static uint KeysymToVirtualKey(IntPtr keysymPtr)
        {
            ulong keysym = (ulong)keysymPtr.ToInt64();

            if (keysym >= 'a' && keysym <= 'z')
                return (uint)(keysym - 'a' + 0x41);

            if (keysym >= 'A' && keysym <= 'Z')
                return (uint)keysym;

            if (keysym >= '0' && keysym <= '9')
                return (uint)keysym;

            if (keysym >= 0xFFB0 && keysym <= 0xFFB9) // XK_KP_0 .. XK_KP_9
                return (uint)(keysym - 0xFFB0 + 0x60);

            if (keysym >= 0xFFBE && keysym <= 0xFFD5) // XK_F1 .. XK_F24
                return (uint)(keysym - 0xFFBE + 0x70);

            switch (keysym)
            {
                case 0x0020: return 0x20; // XK_space
                case 0xFF08: return 0x08; // XK_BackSpace
                case 0xFF09: return 0x09; // XK_Tab
                case 0xFF0D: return 0x0D; // XK_Return
                case 0xFF8D: return 0x0D; // XK_KP_Enter
                case 0xFF13: return 0x13; // XK_Pause
                case 0xFF14: return 0x91; // XK_Scroll_Lock
                case 0xFF1B: return 0x1B; // XK_Escape
                case 0xFF50: return 0x24; // XK_Home
                case 0xFF51: return 0x25; // XK_Left
                case 0xFF52: return 0x26; // XK_Up
                case 0xFF53: return 0x27; // XK_Right
                case 0xFF54: return 0x28; // XK_Down
                case 0xFF55: return 0x21; // XK_Prior
                case 0xFF56: return 0x22; // XK_Next
                case 0xFF57: return 0x23; // XK_End
                case 0xFF61: return 0x2C; // XK_Print
                case 0xFF63: return 0x2D; // XK_Insert
                case 0xFF67: return 0x5D; // XK_Menu
                case 0xFF7F: return 0x90; // XK_Num_Lock
                case 0xFFAA: return 0x6A; // XK_KP_Multiply
                case 0xFFAB: return 0x6B; // XK_KP_Add
                case 0xFFAC: return 0x6C; // XK_KP_Separator
                case 0xFFAD: return 0x6D; // XK_KP_Subtract
                case 0xFFAE: return 0x6E; // XK_KP_Decimal
                case 0xFFAF: return 0x6F; // XK_KP_Divide
                case 0xFFE1: return 0xA0; // XK_Shift_L
                case 0xFFE2: return 0xA1; // XK_Shift_R
                case 0xFFE3: return 0xA2; // XK_Control_L
                case 0xFFE4: return 0xA3; // XK_Control_R
                case 0xFFE5: return 0x14; // XK_Caps_Lock
                case 0xFFE9: return 0xA4; // XK_Alt_L
                case 0xFFEA: return 0xA5; // XK_Alt_R
                case 0xFFEB: return 0x5B; // XK_Super_L
                case 0xFFEC: return 0x5C; // XK_Super_R
                case 0xFFFF: return 0x2E; // XK_Delete
                case 0x003B: return 0xBA; // XK_semicolon
                case 0x003D: return 0xBB; // XK_equal
                case 0x002C: return 0xBC; // XK_comma
                case 0x002D: return 0xBD; // XK_minus
                case 0x002E: return 0xBE; // XK_period
                case 0x002F: return 0xBF; // XK_slash
                case 0x0060: return 0xC0; // XK_grave
                case 0x005B: return 0xDB; // XK_bracketleft
                case 0x005C: return 0xDC; // XK_backslash
                case 0x005D: return 0xDD; // XK_bracketright
                case 0x0027: return 0xDE; // XK_apostrophe
                default: return 0;
            }
        }

        public unsafe bool TranslateVirtualKey(uint virtualKey, uint scanCode, out char character)
        {
            character = '\0';

            if (_xDisplay == IntPtr.Zero || scanCode == 0)
                return false;

            X11.XEvent synthetic = default;
            ref X11.XKeyEvent key = ref Unsafe.As<X11.XEvent, X11.XKeyEvent>(ref synthetic);
            key.Type = X11.KeyPress;
            key.Display = _xDisplay;
            key.State = _modifierState;
            key.Keycode = scanCode & 0xFF;

            lock (_sync)
            {
                if (_windows.Count > 0)
                {
                    foreach (IntPtr handle in _windows.Keys)
                    {
                        key.Window = handle;
                        break;
                    }
                }
            }

            byte* buffer = stackalloc byte[8];
            int written = X11.XLookupString(&synthetic, buffer, 8, out _, IntPtr.Zero);
            if (written <= 0)
                return false;

            character = (char)buffer[0];
            return character != '\0';
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            LinuxWindow[] windows;
            lock (_sync)
            {
                windows = _windows.Values.ToArray();
                _windows.Clear();
            }

            foreach (LinuxWindow window in windows)
                window.Dispose();

            if (_xDisplay != IntPtr.Zero)
            {
                if (_fontStruct != IntPtr.Zero)
                {
                    X11.XFreeFont(_xDisplay, _fontStruct);
                    _fontStruct = IntPtr.Zero;
                }

                if (_gc != IntPtr.Zero)
                {
                    X11.XFreeGC(_xDisplay, _gc);
                    _gc = IntPtr.Zero;
                }

                _pixelCache.Clear();
                X11.XCloseDisplay(_xDisplay);
                _xDisplay = IntPtr.Zero;
            }

            if (_wlDisplay != IntPtr.Zero)
            {
                Wayland.wl_display_disconnect(_wlDisplay);
                _wlDisplay = IntPtr.Zero;
            }
        }

        private IntPtr CreateX11Window(WindowOptions options)
        {
            IntPtr rootWindow = X11.XRootWindow(_xDisplay, _screen);

            int width = Math.Max(options.Width, 1);
            int height = Math.Max(options.Height, 1);

            if (options.Center)
            {
                int screenWidth = X11.XDisplayWidth(_xDisplay, _screen);
                int screenHeight = X11.XDisplayHeight(_xDisplay, _screen);
                options = options with
                {
                    X = Math.Max((screenWidth - width) / 2, 0),
                    Y = Math.Max((screenHeight - height) / 2, 0),
                };
            }

            // Win32 window classes default to a COLOR_WINDOW background; matching it here keeps the
            // black-pen GDI primitives the guest draws from landing on a black surface.
            IntPtr window = X11.XCreateSimpleWindow(
                _xDisplay,
                rootWindow,
                options.X,
                options.Y,
                (uint)width,
                (uint)height,
                0,
                _blackPixel,
                _whitePixel);

            X11.XSelectInput(_xDisplay, window, WindowEventMask);

            IntPtr[] protocols = { _wmDeleteWindow };
            X11.XSetWMProtocols(_xDisplay, window, protocols, protocols.Length);

            SetTitle(window, options.Title ?? string.Empty);
            SetClassHint(window, options.AppId, options.Title);

            if (options.Visible)
                X11.XMapWindow(_xDisplay, window);

            X11.XFlush(_xDisplay);
            return window;
        }

        internal void SetTitle(IntPtr window, string title)
        {
            X11.XStoreName(_xDisplay, window, title);

            byte[] utf8 = Encoding.UTF8.GetBytes(title);
            unsafe
            {
                fixed (byte* data = utf8)
                    X11.XChangeProperty(_xDisplay, window, _netWmName, _utf8String, 8, X11.PropModeReplace, (IntPtr)data, utf8.Length);
            }
        }

        private void SetClassHint(IntPtr window, string? appId, string? title)
        {
            string instance = string.IsNullOrWhiteSpace(appId) ? "brovan" : appId;
            string className = string.IsNullOrWhiteSpace(title) ? instance : title;

            byte[] value = Encoding.UTF8.GetBytes($"{instance}\0{className}\0");
            unsafe
            {
                fixed (byte* data = value)
                    X11.XChangeProperty(_xDisplay, window, (IntPtr)X11.XA_WM_CLASS, (IntPtr)X11.XA_STRING, 8, X11.PropModeReplace, (IntPtr)data, value.Length);
            }
        }

        internal void ApplyDecorations(IntPtr window, bool decorated)
        {
            if (_motifWmHints == IntPtr.Zero)
                return;

            Span<nint> hints = stackalloc nint[5];
            hints.Clear();
            hints[0] = 2;
            hints[2] = decorated ? 1 : 0;

            unsafe
            {
                fixed (nint* data = hints)
                    X11.XChangeProperty(_xDisplay, window, _motifWmHints, _motifWmHints, 32, X11.PropModeReplace, (IntPtr)data, 5);
            }
        }

        internal void ApplySizeHints(IntPtr window, bool resizable, int width, int height)
        {
            X11.XSizeHints hints = default;

            if (resizable)
            {
                hints.Flags = X11.PMinSize;
                hints.MinWidth = 1;
                hints.MinHeight = 1;
            }
            else
            {
                hints.Flags = X11.PMinSize | X11.PMaxSize;
                hints.MinWidth = width;
                hints.MinHeight = height;
                hints.MaxWidth = width;
                hints.MaxHeight = height;
            }

            X11.XSetWMNormalHints(_xDisplay, window, ref hints);
        }

        internal void ApplyState(IntPtr window, WindowState state)
        {
            switch (state)
            {
                case WindowState.Minimized:
                    X11.XIconifyWindow(_xDisplay, window, _screen);
                    break;

                case WindowState.Maximized:
                    SendWmState(window, false, _netWmStateFullscreen, IntPtr.Zero);
                    SendWmState(window, true, _netWmStateMaximizedVert, _netWmStateMaximizedHorz);
                    break;

                case WindowState.Fullscreen:
                    SendWmState(window, true, _netWmStateFullscreen, IntPtr.Zero);
                    break;

                default:
                    SendWmState(window, false, _netWmStateFullscreen, IntPtr.Zero);
                    SendWmState(window, false, _netWmStateMaximizedVert, _netWmStateMaximizedHorz);
                    X11.XMapWindow(_xDisplay, window);
                    break;
            }

            X11.XFlush(_xDisplay);
        }

        private void SendWmState(IntPtr window, bool add, IntPtr firstProperty, IntPtr secondProperty)
        {
            if (_netWmState == IntPtr.Zero || firstProperty == IntPtr.Zero)
                return;

            X11.XEvent nativeEvent = default;
            ref X11.XClientMessageEvent client = ref Unsafe.As<X11.XEvent, X11.XClientMessageEvent>(ref nativeEvent);
            client.Type = X11.ClientMessage;
            client.Window = window;
            client.MessageType = _netWmState;
            client.Format = 32;
            client.Data0 = (IntPtr)(add ? 1 : 0);
            client.Data1 = firstProperty;
            client.Data2 = secondProperty;

            X11.XSendEvent(
                _xDisplay,
                X11.XRootWindow(_xDisplay, _screen),
                0,
                X11.SubstructureNotifyMask | X11.SubstructureRedirectMask,
                ref nativeEvent);
        }

        internal bool DestroyWindow(IntPtr handle)
        {
            if (_xDisplay == IntPtr.Zero || handle == IntPtr.Zero)
                return false;

            bool removed;
            lock (_sync)
                removed = _windows.Remove(handle);

            if (!removed)
                return false;

            X11.XDestroyWindow(_xDisplay, handle);
            X11.XFlush(_xDisplay);
            return true;
        }

        public bool TryGetWindow(IntPtr handle, out LinuxWindow? window)
        {
            lock (_sync)
                return _windows.TryGetValue(handle, out window);
        }

        private IntPtr EnsureGraphicsContext(IntPtr drawable)
        {
            if (_gc != IntPtr.Zero)
                return _gc;

            _gc = X11.XCreateGC(_xDisplay, drawable, 0, IntPtr.Zero);
            if (_gc != IntPtr.Zero && _fontStruct != IntPtr.Zero)
            {
                X11.XSetFont(_xDisplay, _gc, ReadFont().Fid);
            }

            return _gc;
        }

        private X11.XFontStruct ReadFont()
        {
            unsafe
            {
                return *(X11.XFontStruct*)_fontStruct;
            }
        }

        private nuint ResolvePixel(uint colorRef)
        {
            if (_pixelCache.TryGetValue(colorRef, out nuint cached))
                return cached;

            X11.XColor color = default;
            color.Red = (ushort)((colorRef & 0xFF) * 257);
            color.Green = (ushort)(((colorRef >> 8) & 0xFF) * 257);
            color.Blue = (ushort)(((colorRef >> 16) & 0xFF) * 257);
            color.Flags = 0x01 | 0x02 | 0x04;

            nuint pixel = X11.XAllocColor(_xDisplay, _colormap, ref color) != 0 ? color.Pixel : _blackPixel;
            _pixelCache[colorRef] = pixel;
            return pixel;
        }

        public void ExecuteGdiPrimitive(IntPtr windowHandle, GdiPrimitive primitive)
        {
            if (_xDisplay == IntPtr.Zero || windowHandle == IntPtr.Zero)
                return;

            IntPtr gc = EnsureGraphicsContext(windowHandle);
            if (gc == IntPtr.Zero)
                return;

            X11.XSetFunction(_xDisplay, gc, X11.GXcopy);
            X11.XSetLineAttributes(_xDisplay, gc, (uint)Math.Max(primitive.Pen.Width, 1), X11.LineSolid, X11.CapButt, X11.JoinMiter);

            switch (primitive.Kind)
            {
                case GdiPrimitiveKind.Line:
                    X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Pen.ColorRef));
                    X11.XDrawLine(_xDisplay, windowHandle, gc, primitive.X1, primitive.Y1, primitive.X2, primitive.Y2);
                    break;

                case GdiPrimitiveKind.FillRect:
                    FillRect(windowHandle, gc, primitive);
                    break;

                case GdiPrimitiveKind.Rectangle:
                    FillAndOutline(windowHandle, gc, primitive, rounded: false);
                    break;

                case GdiPrimitiveKind.RoundRect:
                    FillAndOutline(windowHandle, gc, primitive, rounded: true);
                    break;

                case GdiPrimitiveKind.Ellipse:
                    {
                        Normalize(primitive, out int x, out int y, out uint width, out uint height);
                        if (primitive.HasBrush)
                        {
                            X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Brush.ColorRef));
                            X11.XFillArc(_xDisplay, windowHandle, gc, x, y, width, height, 0, 360 * 64);
                        }

                        if (primitive.HasPen)
                        {
                            X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Pen.ColorRef));
                            X11.XDrawArc(_xDisplay, windowHandle, gc, x, y, width, height, 0, 360 * 64);
                        }

                        break;
                    }

                case GdiPrimitiveKind.Polygon:
                    {
                        if (primitive.Points == null || primitive.Points.Length == 0)
                            break;

                        X11.XPoint[] points = ToXPoints(primitive.Points, close: true);
                        if (primitive.HasBrush)
                        {
                            X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Brush.ColorRef));
                            X11.XFillPolygon(_xDisplay, windowHandle, gc, points, primitive.Points.Length, X11.Complex, X11.CoordModeOrigin);
                        }

                        if (primitive.HasPen)
                        {
                            X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Pen.ColorRef));
                            X11.XDrawLines(_xDisplay, windowHandle, gc, points, points.Length, X11.CoordModeOrigin);
                        }

                        break;
                    }

                case GdiPrimitiveKind.Polyline:
                    {
                        if (primitive.Points == null || primitive.Points.Length == 0)
                            break;

                        X11.XPoint[] points = ToXPoints(primitive.Points, close: false);
                        X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Pen.ColorRef));
                        X11.XDrawLines(_xDisplay, windowHandle, gc, points, points.Length, X11.CoordModeOrigin);
                        break;
                    }
            }

            X11.XFlush(_xDisplay);
        }

        private void FillRect(IntPtr windowHandle, IntPtr gc, GdiPrimitive primitive)
        {
            Normalize(primitive, out int x, out int y, out uint width, out uint height);

            switch (primitive.Rop)
            {
                case BLACKNESS:
                    X11.XSetForeground(_xDisplay, gc, _blackPixel);
                    break;

                case WHITENESS:
                    X11.XSetForeground(_xDisplay, gc, _whitePixel);
                    break;

                case DSTINVERT:
                    X11.XSetFunction(_xDisplay, gc, X11.GXinvert);
                    break;

                case PATINVERT:
                    X11.XSetFunction(_xDisplay, gc, X11.GXxor);
                    X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Brush.ColorRef));
                    break;

                case PATCOPY:
                default:
                    X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Brush.ColorRef));
                    break;
            }

            X11.XFillRectangle(_xDisplay, windowHandle, gc, x, y, width, height);
        }

        private void FillAndOutline(IntPtr windowHandle, IntPtr gc, GdiPrimitive primitive, bool rounded)
        {
            Normalize(primitive, out int x, out int y, out uint width, out uint height);
            if (width == 0 || height == 0)
                return;

            uint arcWidth = rounded ? (uint)Math.Min(Math.Abs(primitive.RoundedWidth), (int)width) : 0;
            uint arcHeight = rounded ? (uint)Math.Min(Math.Abs(primitive.RoundedHeight), (int)height) : 0;
            bool useArcs = rounded && arcWidth > 1 && arcHeight > 1;

            if (primitive.HasBrush)
            {
                X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Brush.ColorRef));

                if (useArcs)
                    FillRoundRect(windowHandle, gc, x, y, width, height, arcWidth, arcHeight);
                else
                    X11.XFillRectangle(_xDisplay, windowHandle, gc, x, y, width, height);
            }

            if (!primitive.HasPen)
                return;

            X11.XSetForeground(_xDisplay, gc, ResolvePixel(primitive.Pen.ColorRef));

            // Win32 Rectangle excludes the right/bottom edge. XDrawRectangle draws an inclusive border.
            uint outlineWidth = width - 1;
            uint outlineHeight = height - 1;

            if (useArcs)
                OutlineRoundRect(windowHandle, gc, x, y, outlineWidth, outlineHeight, arcWidth, arcHeight);
            else
                X11.XDrawRectangle(_xDisplay, windowHandle, gc, x, y, outlineWidth, outlineHeight);
        }

        private void FillRoundRect(IntPtr windowHandle, IntPtr gc, int x, int y, uint width, uint height, uint arcWidth, uint arcHeight)
        {
            int halfArcWidth = (int)(arcWidth / 2);
            int halfArcHeight = (int)(arcHeight / 2);

            X11.XFillRectangle(_xDisplay, windowHandle, gc, x + halfArcWidth, y, width - arcWidth, height);
            X11.XFillRectangle(_xDisplay, windowHandle, gc, x, y + halfArcHeight, width, height - arcHeight);

            X11.XFillArc(_xDisplay, windowHandle, gc, x, y, arcWidth, arcHeight, 90 * 64, 90 * 64);
            X11.XFillArc(_xDisplay, windowHandle, gc, x + (int)(width - arcWidth), y, arcWidth, arcHeight, 0, 90 * 64);
            X11.XFillArc(_xDisplay, windowHandle, gc, x, y + (int)(height - arcHeight), arcWidth, arcHeight, 180 * 64, 90 * 64);
            X11.XFillArc(_xDisplay, windowHandle, gc, x + (int)(width - arcWidth), y + (int)(height - arcHeight), arcWidth, arcHeight, 270 * 64, 90 * 64);
        }

        private void OutlineRoundRect(IntPtr windowHandle, IntPtr gc, int x, int y, uint width, uint height, uint arcWidth, uint arcHeight)
        {
            int halfArcWidth = (int)(arcWidth / 2);
            int halfArcHeight = (int)(arcHeight / 2);
            int right = x + (int)width;
            int bottom = y + (int)height;

            X11.XDrawLine(_xDisplay, windowHandle, gc, x + halfArcWidth, y, right - halfArcWidth, y);
            X11.XDrawLine(_xDisplay, windowHandle, gc, x + halfArcWidth, bottom, right - halfArcWidth, bottom);
            X11.XDrawLine(_xDisplay, windowHandle, gc, x, y + halfArcHeight, x, bottom - halfArcHeight);
            X11.XDrawLine(_xDisplay, windowHandle, gc, right, y + halfArcHeight, right, bottom - halfArcHeight);

            X11.XDrawArc(_xDisplay, windowHandle, gc, x, y, arcWidth, arcHeight, 90 * 64, 90 * 64);
            X11.XDrawArc(_xDisplay, windowHandle, gc, right - (int)arcWidth, y, arcWidth, arcHeight, 0, 90 * 64);
            X11.XDrawArc(_xDisplay, windowHandle, gc, x, bottom - (int)arcHeight, arcWidth, arcHeight, 180 * 64, 90 * 64);
            X11.XDrawArc(_xDisplay, windowHandle, gc, right - (int)arcWidth, bottom - (int)arcHeight, arcWidth, arcHeight, 270 * 64, 90 * 64);
        }

        private static void Normalize(GdiPrimitive primitive, out int x, out int y, out uint width, out uint height)
        {
            x = Math.Min(primitive.X1, primitive.X2);
            y = Math.Min(primitive.Y1, primitive.Y2);
            width = (uint)Math.Abs(primitive.X2 - primitive.X1);
            height = (uint)Math.Abs(primitive.Y2 - primitive.Y1);
        }

        private static X11.XPoint[] ToXPoints(GdiPoint[] points, bool close)
        {
            bool needsClose = close && points.Length > 2 && (points[0].X != points[^1].X || points[0].Y != points[^1].Y);
            X11.XPoint[] native = new X11.XPoint[points.Length + (needsClose ? 1 : 0)];

            for (int i = 0; i < points.Length; i++)
                native[i] = new X11.XPoint { X = (short)points[i].X, Y = (short)points[i].Y };

            if (needsClose)
                native[^1] = native[0];

            return native;
        }

        public void RenderText(IntPtr windowHandle, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (_xDisplay == IntPtr.Zero || windowHandle == IntPtr.Zero || string.IsNullOrEmpty(text))
                return;

            IntPtr gc = EnsureGraphicsContext(windowHandle);
            if (gc == IntPtr.Zero || _fontStruct == IntPtr.Zero)
                return;

            X11.XFontStruct font = ReadFont();

            X11.XSetFunction(_xDisplay, gc, X11.GXcopy);
            X11.XSetForeground(_xDisplay, gc, _blackPixel);
            X11.XSetBackground(_xDisplay, gc, _whitePixel);

            int textX = x;
            int textY = y + font.Ascent;

            if (rectRight > rectLeft && rectBottom > rectTop)
            {
                int textWidth = X11.XTextWidth(_fontStruct, text, text.Length);
                textX = rectLeft + ((rectRight - rectLeft - textWidth) / 2);
                textY = rectTop + ((rectBottom - rectTop - (font.Ascent + font.Descent)) / 2) + font.Ascent;
            }

            X11.XDrawString(_xDisplay, windowHandle, gc, textX, textY, text, text.Length);
            X11.XFlush(_xDisplay);
        }

        public bool MeasureText(string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            if (_xDisplay == IntPtr.Zero || _fontStruct == IntPtr.Zero || text == null)
                return false;

            X11.XFontStruct font = ReadFont();
            width = text.Length == 0 ? 0 : X11.XTextWidth(_fontStruct, text, text.Length);
            height = font.Ascent + font.Descent;
            return true;
        }

        public bool GetTextMetrics(out TextMetricsData metrics)
        {
            metrics = default;

            if (_xDisplay == IntPtr.Zero || _fontStruct == IntPtr.Zero)
                return false;

            X11.XFontStruct font = ReadFont();

            metrics.Height = font.Ascent + font.Descent;
            metrics.Ascent = font.Ascent;
            metrics.Descent = font.Descent;
            metrics.AveCharWidth = Math.Max(font.MaxWidth / 2, 1);
            metrics.MaxCharWidth = font.MaxWidth;
            metrics.Weight = 400;
            metrics.DigitizedAspectX = 96;
            metrics.DigitizedAspectY = 96;
            metrics.FirstChar = (ushort)font.MinCharOrByte2;
            metrics.LastChar = (ushort)font.MaxCharOrByte2;
            metrics.DefaultChar = (ushort)font.DefaultChar;
            metrics.BreakChar = 0x20;
            metrics.PitchAndFamily = 0x01;
            return true;
        }

        public sealed class LinuxWindow : IWindow
        {
            private readonly LinuxWinManager _manager;
            private readonly IntPtr _display;
            private readonly IntPtr _window;
            private bool _disposed;
            private string _title;
            private int _width;
            private int _height;
            private bool _visible;
            private bool _decorated;
            private WindowState _state;
            private readonly bool _resizable;

            internal LinuxWindow(LinuxWinManager manager, IntPtr display, IntPtr window, WindowOptions options)
            {
                _manager = manager;
                _display = display;
                _window = window;
                _title = options.Title ?? string.Empty;
                _width = Math.Max(options.Width, 1);
                _height = Math.Max(options.Height, 1);
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
                    _manager.SetTitle(_window, _title);
                    X11.XFlush(_display);
                }
            }

            public int Width
            {
                get => _width;
                set
                {
                    EnsureAlive();
                    _width = Math.Max(value, 1);
                    Resize();
                }
            }

            public int Height
            {
                get => _height;
                set
                {
                    EnsureAlive();
                    _height = Math.Max(value, 1);
                    Resize();
                }
            }

            public bool Visible
            {
                get => _visible;
                set
                {
                    EnsureAlive();
                    _visible = value;

                    if (_visible)
                    {
                        X11.XMapWindow(_display, _window);
                        _manager.ApplyState(_window, _state);
                    }
                    else
                    {
                        X11.XUnmapWindow(_display, _window);
                    }

                    X11.XFlush(_display);
                }
            }

            public WindowState State
            {
                get => _state;
                set
                {
                    EnsureAlive();
                    _state = value;

                    if (_visible)
                        _manager.ApplyState(_window, _state);
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
                    _manager.ApplyDecorations(_window, _decorated);
                    X11.XFlush(_display);
                }
            }

            public void Present()
            {
                EnsureAlive();

                _manager.SetTitle(_window, _title);
                _manager.ApplyDecorations(_window, _decorated);
                Resize();

                if (_visible)
                {
                    X11.XMapWindow(_display, _window);
                    _manager.ApplyState(_window, _state);
                }
                else
                {
                    X11.XUnmapWindow(_display, _window);
                }

                X11.XFlush(_display);
            }

            public IntPtr NativeHandle => _window;

            public void Show() => Visible = true;

            public void Hide() => Visible = false;

            public void Close() => Dispose();

            public void Dispose()
            {
                if (_disposed)
                    return;

                _disposed = true;
                _manager.DestroyWindow(_window);
            }

            internal void OnConfigured(int width, int height)
            {
                _width = Math.Max(width, 1);
                _height = Math.Max(height, 1);
            }

            private void Resize()
            {
                _manager.ApplySizeHints(_window, _resizable, _width, _height);
                X11.XResizeWindow(_display, _window, (uint)_width, (uint)_height);
                X11.XFlush(_display);
            }

            private void EnsureAlive()
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(LinuxWindow));
            }
        }
    }
}
