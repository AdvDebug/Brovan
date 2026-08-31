using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal readonly struct Win32kMessage
    {
        public readonly ulong Hwnd;
        public readonly uint Message;
        public readonly ulong WParam;
        public readonly ulong LParam;
        public readonly uint Time;
        public readonly int X;
        public readonly int Y;

        public Win32kMessage(ulong Hwnd, uint Message, ulong WParam, ulong LParam, uint Time, int X, int Y)
        {
            this.Hwnd = Hwnd;
            this.Message = Message;
            this.WParam = WParam;
            this.LParam = LParam;
            this.Time = Time;
            this.X = X;
            this.Y = Y;
        }
    }

    internal struct Win32kPenBrush
    {
        public bool IsPen;
        public uint ColorRef;
        public int PenWidth;
    }

    internal readonly struct Win32kKeyMapping
    {
        public readonly byte ScanCode;
        public readonly bool Extended;
        public readonly byte VirtualKey;
        public readonly byte SidedVirtualKey;
        public readonly char Character;
        public readonly char ShiftedCharacter;

        public Win32kKeyMapping(byte ScanCode, bool Extended, byte VirtualKey, byte SidedVirtualKey, char Character, char ShiftedCharacter)
        {
            this.ScanCode = ScanCode;
            this.Extended = Extended;
            this.VirtualKey = VirtualKey;
            this.SidedVirtualKey = SidedVirtualKey;
            this.Character = Character;
            this.ShiftedCharacter = ShiftedCharacter;
        }
    }

    internal struct Win32kWindowClassDefinition
    {
        public uint cbSize;
        public uint style;
        public ulong lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public ulong hInstance;
        public ulong hIcon;
        public ulong hCursor;
        public ulong hbrBackground;
        public ulong lpszMenuName;
        public ulong lpszClassName;
        public ulong hIconSm;
    }

    internal struct Win32kBitmap
    {
        public int Width;
        public int Height;
        public ushort Planes;
        public ushort BitsPerPixel;
        public int Stride;
        public ulong BitsAddress;
        public uint BitsSize;
        public bool DibSection;
        public bool TopDown;
    }

    internal static class Win32kHelper
    {
        internal const uint ERROR_SUCCESS = 0;
        internal const uint ERROR_INVALID_HANDLE = 6;
        internal const uint ERROR_ACCESS_DENIED = 5;
        internal const uint ERROR_INVALID_PARAMETER = 87;
        internal const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
        internal const uint ERROR_INSUFFICIENT_BUFFER = 122;
        internal const uint ERROR_INVALID_WINDOW_HANDLE = 1400;
        internal const uint ERROR_CANNOT_FIND_WND_CLASS = 1407;

        internal const int MaxClassExtraBytes = 0x10000;

        internal const string KeyboardPreloadKey = @"\Keyboard Layout\Preload";
        internal const string KeyboardLayoutsKey = @"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Keyboard Layouts";

        internal const byte PenHandleType = 0x30;
        internal const byte BrushHandleType = 0x10;
        internal const byte BitmapHandleType = 0x05;
        internal const byte FontHandleType = 0x0A;

        internal const uint WM_NULL = 0x0000;
        internal const uint WM_CREATE = 0x0001;
        internal const uint WM_DESTROY = 0x0002;
        internal const uint WM_NCCREATE = 0x0081;
        internal const uint WM_SIZE = 0x0005;
        internal const uint WM_ACTIVATE = 0x0006;
        internal const uint WM_SETFOCUS = 0x0007;
        internal const uint WM_KILLFOCUS = 0x0008;
        internal const uint WM_ACTIVATEAPP = 0x001C;
        internal const uint WM_MOVE = 0x0003;
        internal const uint WM_WINDOWPOSCHANGED = 0x0047;
        internal const uint SIZE_MINIMIZED = 1;
        internal const uint SIZE_MAXIMIZED = 2;
        internal const uint WM_CLOSE = 0x0010;
        internal const uint WM_QUIT = 0x0012;
        internal const uint WM_ERASEBKGND = 0x0014;
        internal const uint WM_SETCURSOR = 0x0020;
        internal const uint WM_GETTEXT = 0x000D;
        internal const uint WM_GETTEXTLENGTH = 0x000E;
        internal const uint WM_NCHITTEST = 0x0084;
        internal const uint WM_CTLCOLORMSGBOX = 0x0132;
        internal const uint WM_CTLCOLOREDIT = 0x0133;
        internal const uint WM_CTLCOLORLISTBOX = 0x0134;
        internal const uint WM_CTLCOLORBTN = 0x0135;
        internal const uint WM_CTLCOLORDLG = 0x0136;
        internal const uint WM_CTLCOLORSCROLLBAR = 0x0137;
        internal const uint WM_CTLCOLORSTATIC = 0x0138;

        internal const int COLOR_SCROLLBAR = 0;
        internal const int COLOR_WINDOW = 5;
        internal const int COLOR_BTNFACE = 15;
        internal const uint WM_NCDESTROY = 0x0082;
        internal const uint WM_PAINT = 0x000F;
        internal const uint WM_SETTEXT = 0x000C;
        internal const uint WM_KEYDOWN = 0x0100;
        internal const uint WM_KEYUP = 0x0101;
        internal const uint WM_CHAR = 0x0102;
        internal const uint WM_SYSKEYDOWN = 0x0104;
        internal const uint WM_SYSKEYUP = 0x0105;
        internal const uint WM_SYSCHAR = 0x0106;
        internal const uint WM_DPICHANGED = 0x02E0;
        internal const uint WM_INPUT = 0x00FF;
        internal const uint WM_MOUSEMOVE = 0x0200;
        internal const uint WM_LBUTTONDOWN = 0x0201;
        internal const uint WM_LBUTTONUP = 0x0202;
        internal const uint WM_RBUTTONDOWN = 0x0204;
        internal const uint WM_RBUTTONUP = 0x0205;

        internal const uint QS_KEY = 0x0001;
        internal const uint QS_MOUSEMOVE = 0x0002;
        internal const uint QS_MOUSEBUTTON = 0x0004;
        internal const uint QS_POSTMESSAGE = 0x0008;
        internal const uint QS_TIMER = 0x0010;
        internal const uint QS_PAINT = 0x0020;
        internal const uint QS_SENDMESSAGE = 0x0040;
        internal const uint QS_HOTKEY = 0x0080;
        internal const uint QS_ALLPOSTMESSAGE = 0x0100;
        internal const uint QS_RAWINPUT = 0x0400;
        internal const uint QS_TOUCH = 0x0800;
        internal const uint QS_POINTER = 0x1000;
        internal const uint QS_MOUSE = QS_MOUSEMOVE | QS_MOUSEBUTTON;
        internal const uint QS_INPUT = QS_MOUSE | QS_KEY | QS_RAWINPUT | QS_TOUCH | QS_POINTER;
        internal const uint QS_ALLEVENTS = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY;
        internal const uint QS_ALLINPUT = QS_ALLEVENTS | QS_SENDMESSAGE;

        private const uint WA_INACTIVE = 0;
        private const uint WA_ACTIVE = 1;

        private const int HTCLIENT = 1;
        private const ulong HWND_BROADCAST = 0xFFFF;
        private const ulong FirstDeviceContextHandle = 0x770001;
        private const uint PM_REMOVE = 0x0001;
        private const int MSG64_SIZE = 48;
        private const int MSG32_SIZE = 28;
        private const int PAINTSTRUCT64_SIZE = 72;
        private const int PAINTSTRUCT32_SIZE = 64;
        private const int MaxWindowTextBytes = 0x1000;
        private const long MaxBitmapBytes = 0x40000000;
        private const uint BitmapCopyChunkBytes = 0x10000;

        private static readonly ConditionalWeakTable<BinaryEmulator, Win32kState> States = new();

        private sealed class Win32kState
        {
            public readonly Queue<Win32kMessage> MessageQueue = new();
            public readonly Dictionary<ulong, Win32kDeviceContext> DeviceContexts = new();
            public readonly Dictionary<ulong, Win32kPenBrush> PenBrushObjects = new();
            public readonly Dictionary<ulong, Win32kBitmap> Bitmaps = new();
            public readonly Dictionary<ulong, Win32kFont> Fonts = new();

            // Advance width per character, biased by one so that zero reads as unmeasured.
            public readonly Dictionary<IntPtr, int[]> CharAdvanceWidthsByFont = new();

            public ulong StockBitmap;
            public ulong NextDeviceContext = FirstDeviceContextHandle;
            public ulong CaptureWindow;
            public ulong ActivatedWindow;
            public bool QuitPosted;
            public ulong QuitExitCode;
            public int CursorX;
            public int CursorY;
            public ulong CursorHandle;
            public ulong StockCursor;
            public bool CursorAssigned;
            public int CursorShowCount;
            public bool CursorHidden;
            public bool CursorHiddenWhileTyping;
            public Win32kCaret Caret;

            public uint QueuedWakeBits;
            public bool QueuedWakeBitsValid;

            public IReadOnlyList<uint> KeyboardLayouts;
            public uint KeyboardLayoutsGeneration;
        }

        internal sealed class Win32kCaret
        {
            public ulong Hwnd;
            public ulong Bitmap;
            public int X;
            public int Y;
            public int Width;
            public int Height;
            public int ShowCount;
        }

        private sealed class Win32kFont
        {
            public FontDescription Description;
            public IntPtr HostFont;
        }

        private sealed class Win32kDeviceContext
        {
            public ulong Handle;
            public ulong Hwnd;
            public bool WindowDc;
            public bool PaintDc;
            public ulong SelectedBitmap;
            public ulong SelectedFont;
            public uint BoundsFlags;
            public int BoundsLeft;
            public int BoundsTop;
            public int BoundsRight;
            public int BoundsBottom;
        }

        private static Win32kState GetState(BinaryEmulator Instance)
        {
            return States.GetValue(Instance, static _ => new Win32kState());
        }

        internal static bool CreateCaret(BinaryEmulator Instance, ulong Hwnd, ulong Bitmap, int Width, int Height)
        {
            if (Instance.WinHelper.GetWindow(Hwnd) == null)
                return false;

            GetState(Instance).Caret = new Win32kCaret
            {
                Hwnd = Hwnd,
                Bitmap = Bitmap,
                Width = Width,
                Height = Height,
                ShowCount = 0,
            };
            return true;
        }

        internal static bool DestroyCaret(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            if (State.Caret == null)
                return false;

            State.Caret = null;
            return true;
        }

        internal static Win32kCaret GetOwnedCaret(BinaryEmulator Instance, ulong Hwnd)
        {
            Win32kCaret Caret = GetState(Instance).Caret;
            if (Caret == null)
                return null;

            return Hwnd == 0 || Caret.Hwnd == Hwnd ? Caret : null;
        }

        internal static ulong GetCaptureWindow(BinaryEmulator Instance)
        {
            return GetState(Instance).CaptureWindow;
        }

        internal static ulong SetCaptureWindow(BinaryEmulator Instance, ulong Hwnd)
        {
            Win32kState State = GetState(Instance);
            ulong Previous = State.CaptureWindow;
            State.CaptureWindow = Hwnd;
            Instance.WinHelper.SetUserCaptureActive(Hwnd != 0);
            return Previous;
        }

        internal static bool IsKnownWindow(BinaryEmulator Instance, ulong Hwnd)
        {
            return Hwnd == 0 || Instance.WinHelper.GetWindow(Hwnd) != null;
        }

        internal static ulong CreateDeviceContext(BinaryEmulator Instance, ulong Hwnd, bool WindowDc, bool PaintDc)
        {
            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
                return 0;

            ulong GdiHandle = Instance.WinHelper.AllocateGdiHandle(0x01);
            if (GdiHandle == 0)
                return 0;

            Win32kState State = GetState(Instance);
            State.DeviceContexts[GdiHandle] = new Win32kDeviceContext
            {
                Handle = GdiHandle,
                Hwnd = Hwnd,
                WindowDc = WindowDc,
                PaintDc = PaintDc,
                SelectedBitmap = EnsureStockBitmap(Instance),
            };
            return GdiHandle;
        }

        internal static bool ReleaseDeviceContext(BinaryEmulator Instance, ulong Hdc)
        {
            if (Hdc == 0)
                return false;

            Win32kState State = GetState(Instance);
            if (!State.DeviceContexts.Remove(Hdc))
                return false;

            Instance.WinHelper.FreeGdiHandle(Hdc);
            return true;
        }

        internal static ulong GetHwndFromDc(BinaryEmulator Instance, ulong Hdc)
        {
            if (Hdc == 0)
                return 0;

            Win32kState State = GetState(Instance);
            if (State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return Dc.Hwnd;

            return 0;
        }

        internal static bool IsKnownDc(BinaryEmulator Instance, ulong Hdc)
        {
            if (Hdc == 0)
                return false;

            return GetState(Instance).DeviceContexts.ContainsKey(Hdc);
        }

        internal static bool TrySelectDcBitmap(BinaryEmulator Instance, ulong Hdc, ulong Bitmap, out ulong Previous)
        {
            Previous = 0;

            Win32kState State = GetState(Instance);
            if (!State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return false;

            Previous = Dc.SelectedBitmap != 0 ? Dc.SelectedBitmap : EnsureStockBitmap(Instance);
            Dc.SelectedBitmap = Bitmap;
            return true;
        }

        internal static bool TrySetDcBounds(BinaryEmulator Instance, ulong Hdc, uint Flags, bool HasRect,
            int Left, int Top, int Right, int Bottom, out uint Previous)
        {
            const uint DcbReset = 0x0001;
            const uint DcbAccumulate = 0x0002;
            const uint DcbEnable = 0x0004;
            const uint DcbDisable = 0x0008;

            Previous = 0;

            Win32kState State = GetState(Instance);
            if (!State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return false;

            Previous = Dc.BoundsFlags == 0 ? DcbDisable : Dc.BoundsFlags;

            bool Empty = (Flags & DcbReset) != 0 ||
                (Dc.BoundsRight <= Dc.BoundsLeft && Dc.BoundsBottom <= Dc.BoundsTop);

            if ((Flags & DcbReset) != 0)
            {
                Dc.BoundsLeft = 0;
                Dc.BoundsTop = 0;
                Dc.BoundsRight = 0;
                Dc.BoundsBottom = 0;
            }

            if (HasRect && (Flags & DcbAccumulate) != 0 && (Right != Left || Bottom != Top))
            {
                int NewLeft = Math.Min(Left, Right);
                int NewTop = Math.Min(Top, Bottom);
                int NewRight = Math.Max(Left, Right);
                int NewBottom = Math.Max(Top, Bottom);

                Dc.BoundsLeft = Empty ? NewLeft : Math.Min(Dc.BoundsLeft, NewLeft);
                Dc.BoundsTop = Empty ? NewTop : Math.Min(Dc.BoundsTop, NewTop);
                Dc.BoundsRight = Empty ? NewRight : Math.Max(Dc.BoundsRight, NewRight);
                Dc.BoundsBottom = Empty ? NewBottom : Math.Max(Dc.BoundsBottom, NewBottom);
            }

            if ((Flags & (DcbEnable | DcbDisable)) != 0)
                Dc.BoundsFlags = Flags & (DcbEnable | DcbDisable);

            return true;
        }

        internal static ulong CreatePen(BinaryEmulator Instance, int Style, int Width, uint ColorRef)
        {
            ulong Handle = Instance.WinHelper.AllocateGdiHandle(PenHandleType);
            if (Handle == 0)
                return 0;

            GetState(Instance).PenBrushObjects[Handle] = new Win32kPenBrush
            {
                IsPen = true,
                ColorRef = ColorRef,
                PenWidth = Width,
            };
            return Handle;
        }

        internal static ulong CreateFont(BinaryEmulator Instance, in FontDescription Description)
        {
            IntPtr HostFont = Instance.WinHelper.CreateHostFont(Description);
            if (HostFont == IntPtr.Zero)
                return 0;

            ulong Handle = Instance.WinHelper.AllocateGdiHandle(FontHandleType);
            if (Handle == 0)
            {
                Instance.WinHelper.DeleteHostFont(HostFont);
                return 0;
            }

            GetState(Instance).Fonts[Handle] = new Win32kFont { Description = Description, HostFont = HostFont };
            return Handle;
        }

        internal static bool RemoveFont(BinaryEmulator Instance, ulong Handle)
        {
            Win32kState State = GetState(Instance);
            if (!State.Fonts.Remove(Handle, out Win32kFont Font))
                return false;

            State.CharAdvanceWidthsByFont.Remove(Font.HostFont);
            Instance.WinHelper.DeleteHostFont(Font.HostFont);
            return true;
        }

        internal static ulong SelectFont(BinaryEmulator Instance, ulong Hdc, ulong Font)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Context))
                return 0;

            ulong Previous = Context.SelectedFont;
            Context.SelectedFont = Font;
            return Previous;
        }

        // A device context with no font selected uses the message font SERVERINFO advertises.
        internal static IntPtr ResolveDcFont(BinaryEmulator Instance, ulong Hdc)
        {
            Win32kFont Font = ResolveDcFontObject(Instance, Hdc);
            return Font != null ? Font.HostFont : Instance.WinHelper.EnsureDefaultTextFont();
        }

        internal static string GetDcFaceName(BinaryEmulator Instance, ulong Hdc)
        {
            return ResolveDcFontObject(Instance, Hdc)?.Description.FaceName ?? Instance.WinHelper.DefaultFaceName;
        }

        internal static byte GetDcCharSet(BinaryEmulator Instance, ulong Hdc)
        {
            Win32kFont Font = ResolveDcFontObject(Instance, Hdc);
            return Font != null ? Font.Description.CharSet : DefaultCharSet;
        }

        private const byte DefaultCharSet = 1;

        private static Win32kFont ResolveDcFontObject(BinaryEmulator Instance, ulong Hdc)
        {
            Win32kState State = GetState(Instance);
            if (Hdc != 0 && State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Context) &&
                Context.SelectedFont != 0 && State.Fonts.TryGetValue(Context.SelectedFont, out Win32kFont Font))
            {
                return Font;
            }

            return null;
        }

        internal static ulong CreateSolidBrush(BinaryEmulator Instance, uint ColorRef)
        {
            ulong Handle = Instance.WinHelper.AllocateGdiHandle(BrushHandleType);
            if (Handle == 0)
                return 0;

            GetState(Instance).PenBrushObjects[Handle] = new Win32kPenBrush
            {
                IsPen = false,
                ColorRef = ColorRef,
            };
            return Handle;
        }

        internal static Win32kPenBrush ResolvePenBrush(BinaryEmulator Instance, ulong Handle, bool IsPen)
        {
            if (Handle != 0 && GetState(Instance).PenBrushObjects.TryGetValue(Handle, out Win32kPenBrush Found))
                return Found;

            return new Win32kPenBrush { IsPen = IsPen, ColorRef = 0x00000000, PenWidth = 1 };
        }

        internal static bool TryGetPenBrush(BinaryEmulator Instance, ulong Handle, out Win32kPenBrush PenBrush)
        {
            if (Handle != 0)
                return GetState(Instance).PenBrushObjects.TryGetValue(Handle, out PenBrush);

            PenBrush = default;
            return false;
        }

        internal static bool RemovePenBrush(BinaryEmulator Instance, ulong Handle)
        {
            return GetState(Instance).PenBrushObjects.Remove(Handle);
        }

        internal const uint MapVirtualKeyToScanCode = 0;
        internal const uint MapVirtualScanCodeToKey = 1;
        internal const uint MapVirtualKeyToChar = 2;
        internal const uint MapVirtualScanCodeToKeyEx = 3;
        internal const uint MapVirtualKeyToScanCodeEx = 4;

        internal const byte VkBack = 0x08;
        internal const byte VkTab = 0x09;
        internal const byte VkReturn = 0x0D;
        internal const byte VkShift = 0x10;
        internal const byte VkControl = 0x11;
        internal const byte VkMenu = 0x12;
        internal const byte VkPause = 0x13;
        internal const byte VkCapital = 0x14;
        internal const byte VkEscape = 0x1B;
        internal const byte VkSpace = 0x20;
        internal const byte VkPrior = 0x21;
        internal const byte VkNext = 0x22;
        internal const byte VkEnd = 0x23;
        internal const byte VkHome = 0x24;
        internal const byte VkLeft = 0x25;
        internal const byte VkUp = 0x26;
        internal const byte VkRight = 0x27;
        internal const byte VkDown = 0x28;
        internal const byte VkSnapshot = 0x2C;
        internal const byte VkInsert = 0x2D;
        internal const byte VkDelete = 0x2E;
        internal const byte VkLWin = 0x5B;
        internal const byte VkRWin = 0x5C;
        internal const byte VkApps = 0x5D;
        internal const byte VkNumpad0 = 0x60;
        internal const byte VkMultiply = 0x6A;
        internal const byte VkAdd = 0x6B;
        internal const byte VkSubtract = 0x6D;
        internal const byte VkDecimal = 0x6E;
        internal const byte VkDivide = 0x6F;
        internal const byte VkF1 = 0x70;
        internal const byte VkNumLock = 0x90;
        internal const byte VkScroll = 0x91;
        internal const byte VkLShift = 0xA0;
        internal const byte VkRShift = 0xA1;
        internal const byte VkLControl = 0xA2;
        internal const byte VkRControl = 0xA3;
        internal const byte VkLMenu = 0xA4;
        internal const byte VkRMenu = 0xA5;
        internal const byte VkOem1 = 0xBA;
        internal const byte VkOemPlus = 0xBB;
        internal const byte VkOemComma = 0xBC;
        internal const byte VkOemMinus = 0xBD;
        internal const byte VkOemPeriod = 0xBE;
        internal const byte VkOem2 = 0xBF;
        internal const byte VkOem3 = 0xC0;
        internal const byte VkOem4 = 0xDB;
        internal const byte VkOem5 = 0xDC;
        internal const byte VkOem6 = 0xDD;
        internal const byte VkOem7 = 0xDE;
        internal const byte VkOem102 = 0xE2;

        internal const uint ExtendedScanCodePrefix = 0xE000;

        /// <summary>
        /// US layout, set 1 scan codes. Non-extended rows come first so a virtual-key lookup resolves to the
        /// main-keyboard scan code the way MapVirtualKey does (VK_RETURN to 0x1C, not to the numpad's 0xE01C).
        /// </summary>
        private static readonly Win32kKeyMapping[] KeyMappings =
        {
            new(0x01, false, VkEscape, VkEscape, '\x1B', '\x1B'),
            new(0x02, false, (byte)'1', (byte)'1', '1', '!'),
            new(0x03, false, (byte)'2', (byte)'2', '2', '@'),
            new(0x04, false, (byte)'3', (byte)'3', '3', '#'),
            new(0x05, false, (byte)'4', (byte)'4', '4', '$'),
            new(0x06, false, (byte)'5', (byte)'5', '5', '%'),
            new(0x07, false, (byte)'6', (byte)'6', '6', '^'),
            new(0x08, false, (byte)'7', (byte)'7', '7', '&'),
            new(0x09, false, (byte)'8', (byte)'8', '8', '*'),
            new(0x0A, false, (byte)'9', (byte)'9', '9', '('),
            new(0x0B, false, (byte)'0', (byte)'0', '0', ')'),
            new(0x0C, false, VkOemMinus, VkOemMinus, '-', '_'),
            new(0x0D, false, VkOemPlus, VkOemPlus, '=', '+'),
            new(0x0E, false, VkBack, VkBack, '\b', '\b'),
            new(0x0F, false, VkTab, VkTab, '\t', '\t'),
            new(0x10, false, (byte)'Q', (byte)'Q', 'q', 'Q'),
            new(0x11, false, (byte)'W', (byte)'W', 'w', 'W'),
            new(0x12, false, (byte)'E', (byte)'E', 'e', 'E'),
            new(0x13, false, (byte)'R', (byte)'R', 'r', 'R'),
            new(0x14, false, (byte)'T', (byte)'T', 't', 'T'),
            new(0x15, false, (byte)'Y', (byte)'Y', 'y', 'Y'),
            new(0x16, false, (byte)'U', (byte)'U', 'u', 'U'),
            new(0x17, false, (byte)'I', (byte)'I', 'i', 'I'),
            new(0x18, false, (byte)'O', (byte)'O', 'o', 'O'),
            new(0x19, false, (byte)'P', (byte)'P', 'p', 'P'),
            new(0x1A, false, VkOem4, VkOem4, '[', '{'),
            new(0x1B, false, VkOem6, VkOem6, ']', '}'),
            new(0x1C, false, VkReturn, VkReturn, '\r', '\r'),
            new(0x1D, false, VkControl, VkLControl, '\0', '\0'),
            new(0x1E, false, (byte)'A', (byte)'A', 'a', 'A'),
            new(0x1F, false, (byte)'S', (byte)'S', 's', 'S'),
            new(0x20, false, (byte)'D', (byte)'D', 'd', 'D'),
            new(0x21, false, (byte)'F', (byte)'F', 'f', 'F'),
            new(0x22, false, (byte)'G', (byte)'G', 'g', 'G'),
            new(0x23, false, (byte)'H', (byte)'H', 'h', 'H'),
            new(0x24, false, (byte)'J', (byte)'J', 'j', 'J'),
            new(0x25, false, (byte)'K', (byte)'K', 'k', 'K'),
            new(0x26, false, (byte)'L', (byte)'L', 'l', 'L'),
            new(0x27, false, VkOem1, VkOem1, ';', ':'),
            new(0x28, false, VkOem7, VkOem7, '\'', '"'),
            new(0x29, false, VkOem3, VkOem3, '`', '~'),
            new(0x2A, false, VkShift, VkLShift, '\0', '\0'),
            new(0x2B, false, VkOem5, VkOem5, '\\', '|'),
            new(0x2C, false, (byte)'Z', (byte)'Z', 'z', 'Z'),
            new(0x2D, false, (byte)'X', (byte)'X', 'x', 'X'),
            new(0x2E, false, (byte)'C', (byte)'C', 'c', 'C'),
            new(0x2F, false, (byte)'V', (byte)'V', 'v', 'V'),
            new(0x30, false, (byte)'B', (byte)'B', 'b', 'B'),
            new(0x31, false, (byte)'N', (byte)'N', 'n', 'N'),
            new(0x32, false, (byte)'M', (byte)'M', 'm', 'M'),
            new(0x33, false, VkOemComma, VkOemComma, ',', '<'),
            new(0x34, false, VkOemPeriod, VkOemPeriod, '.', '>'),
            new(0x35, false, VkOem2, VkOem2, '/', '?'),
            new(0x36, false, VkShift, VkRShift, '\0', '\0'),
            new(0x37, false, VkMultiply, VkMultiply, '*', '*'),
            new(0x38, false, VkMenu, VkLMenu, '\0', '\0'),
            new(0x39, false, VkSpace, VkSpace, ' ', ' '),
            new(0x3A, false, VkCapital, VkCapital, '\0', '\0'),
            new(0x3B, false, VkF1 + 0, VkF1 + 0, '\0', '\0'),
            new(0x3C, false, VkF1 + 1, VkF1 + 1, '\0', '\0'),
            new(0x3D, false, VkF1 + 2, VkF1 + 2, '\0', '\0'),
            new(0x3E, false, VkF1 + 3, VkF1 + 3, '\0', '\0'),
            new(0x3F, false, VkF1 + 4, VkF1 + 4, '\0', '\0'),
            new(0x40, false, VkF1 + 5, VkF1 + 5, '\0', '\0'),
            new(0x41, false, VkF1 + 6, VkF1 + 6, '\0', '\0'),
            new(0x42, false, VkF1 + 7, VkF1 + 7, '\0', '\0'),
            new(0x43, false, VkF1 + 8, VkF1 + 8, '\0', '\0'),
            new(0x44, false, VkF1 + 9, VkF1 + 9, '\0', '\0'),
            new(0x45, false, VkNumLock, VkNumLock, '\0', '\0'),
            new(0x46, false, VkScroll, VkScroll, '\0', '\0'),
            new(0x47, false, VkNumpad0 + 7, VkNumpad0 + 7, '7', '7'),
            new(0x48, false, VkNumpad0 + 8, VkNumpad0 + 8, '8', '8'),
            new(0x49, false, VkNumpad0 + 9, VkNumpad0 + 9, '9', '9'),
            new(0x4A, false, VkSubtract, VkSubtract, '-', '-'),
            new(0x4B, false, VkNumpad0 + 4, VkNumpad0 + 4, '4', '4'),
            new(0x4C, false, VkNumpad0 + 5, VkNumpad0 + 5, '5', '5'),
            new(0x4D, false, VkNumpad0 + 6, VkNumpad0 + 6, '6', '6'),
            new(0x4E, false, VkAdd, VkAdd, '+', '+'),
            new(0x4F, false, VkNumpad0 + 1, VkNumpad0 + 1, '1', '1'),
            new(0x50, false, VkNumpad0 + 2, VkNumpad0 + 2, '2', '2'),
            new(0x51, false, VkNumpad0 + 3, VkNumpad0 + 3, '3', '3'),
            new(0x52, false, VkNumpad0 + 0, VkNumpad0 + 0, '0', '0'),
            new(0x53, false, VkDecimal, VkDecimal, '.', '.'),
            new(0x56, false, VkOem102, VkOem102, '\\', '|'),
            new(0x57, false, VkF1 + 10, VkF1 + 10, '\0', '\0'),
            new(0x58, false, VkF1 + 11, VkF1 + 11, '\0', '\0'),
            new(0x45, false, VkPause, VkPause, '\0', '\0'),
            new(0x1C, true, VkReturn, VkReturn, '\r', '\r'),
            new(0x1D, true, VkControl, VkRControl, '\0', '\0'),
            new(0x35, true, VkDivide, VkDivide, '/', '/'),
            new(0x37, true, VkSnapshot, VkSnapshot, '\0', '\0'),
            new(0x38, true, VkMenu, VkRMenu, '\0', '\0'),
            new(0x47, true, VkHome, VkHome, '\0', '\0'),
            new(0x48, true, VkUp, VkUp, '\0', '\0'),
            new(0x49, true, VkPrior, VkPrior, '\0', '\0'),
            new(0x4B, true, VkLeft, VkLeft, '\0', '\0'),
            new(0x4D, true, VkRight, VkRight, '\0', '\0'),
            new(0x4F, true, VkEnd, VkEnd, '\0', '\0'),
            new(0x50, true, VkDown, VkDown, '\0', '\0'),
            new(0x51, true, VkNext, VkNext, '\0', '\0'),
            new(0x52, true, VkInsert, VkInsert, '\0', '\0'),
            new(0x53, true, VkDelete, VkDelete, '\0', '\0'),
            new(0x5B, true, VkLWin, VkLWin, '\0', '\0'),
            new(0x5C, true, VkRWin, VkRWin, '\0', '\0'),
            new(0x5D, true, VkApps, VkApps, '\0', '\0'),
        };

        internal static uint MapVirtualKey(uint Code, uint MapType)
        {
            switch (MapType)
            {
                case MapVirtualKeyToScanCode:
                case MapVirtualKeyToScanCodeEx:
                {
                    for (int i = 0; i < KeyMappings.Length; i++)
                    {
                        Win32kKeyMapping Mapping = KeyMappings[i];
                        if (Mapping.VirtualKey != Code && Mapping.SidedVirtualKey != Code)
                            continue;

                        if (MapType == MapVirtualKeyToScanCodeEx && Mapping.Extended)
                            return ExtendedScanCodePrefix | Mapping.ScanCode;

                        return Mapping.ScanCode;
                    }

                    return 0;
                }

                case MapVirtualScanCodeToKey:
                case MapVirtualScanCodeToKeyEx:
                {
                    bool Extended = (Code & 0xFF00) == ExtendedScanCodePrefix;
                    byte ScanCode = (byte)Code;

                    for (int i = 0; i < KeyMappings.Length; i++)
                    {
                        Win32kKeyMapping Mapping = KeyMappings[i];
                        if (Mapping.ScanCode != ScanCode || Mapping.Extended != Extended)
                            continue;

                        return MapType == MapVirtualScanCodeToKeyEx ? Mapping.SidedVirtualKey : Mapping.VirtualKey;
                    }

                    return 0;
                }

                case MapVirtualKeyToChar:
                {
                    if (!TryGetKeyMapping(Code, out Win32kKeyMapping Mapping) || Mapping.Character == '\0')
                        return 0;

                    return char.ToUpperInvariant(Mapping.Character);
                }
            }

            return 0;
        }

        internal static bool TryTranslateKey(uint VirtualKey, bool Shift, bool CapsLock, bool Control, out char Character)
        {
            Character = '\0';
            if (!TryGetKeyMapping(VirtualKey, out Win32kKeyMapping Mapping))
                return false;

            char Translated = Shift ? Mapping.ShiftedCharacter : Mapping.Character;
            if (Translated == '\0')
                return false;

            if (CapsLock && char.IsAsciiLetter(Mapping.Character))
                Translated = Shift ? Mapping.Character : Mapping.ShiftedCharacter;

            if (Control)
            {
                if (!char.IsAsciiLetter(Translated))
                    return false;

                Translated = (char)(char.ToUpperInvariant(Translated) - 'A' + 1);
            }

            Character = Translated;
            return true;
        }

        private static bool TryGetKeyMapping(uint VirtualKey, out Win32kKeyMapping Mapping)
        {
            for (int i = 0; i < KeyMappings.Length; i++)
            {
                if (KeyMappings[i].VirtualKey == VirtualKey || KeyMappings[i].SidedVirtualKey == VirtualKey)
                {
                    Mapping = KeyMappings[i];
                    return true;
                }
            }

            Mapping = default;
            return false;
        }

        /// <summary>
        /// Byte length of one scanline. GDI pads plain bitmaps to a WORD and DIB sections to a DWORD.
        /// </summary>
        internal static int GetBitmapStride(int Width, int Planes, int BitsPerPixel, bool DibSection)
        {
            long Bits = (long)Width * Planes * BitsPerPixel;
            if (Bits <= 0 || Bits > int.MaxValue)
                return 0;

            return DibSection ? (int)(((Bits + 31) / 32) * 4) : (int)(((Bits + 15) / 16) * 2);
        }

        // Every DC starts on this, so a caller that selects its own bitmap has one to select back.
        internal static ulong EnsureStockBitmap(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            if (State.StockBitmap == 0)
                State.StockBitmap = CreateBitmap(Instance, 1, 1, 1, 1, false, false);

            return State.StockBitmap;
        }

        internal static ulong CreateBitmap(BinaryEmulator Instance, int Width, int Height, ushort Planes, ushort BitsPerPixel, bool DibSection, bool TopDown)
        {
            int Stride = GetBitmapStride(Width, Planes, BitsPerPixel, DibSection);
            if (Width <= 0 || Height <= 0 || Planes == 0 || BitsPerPixel == 0 || Stride == 0)
                return 0;

            long TotalBytes = (long)Stride * Height;
            if (TotalBytes > MaxBitmapBytes)
                return 0;

            ulong Handle = Instance.WinHelper.AllocateGdiHandle(BitmapHandleType);
            if (Handle == 0)
                return 0;

            ulong BitsAddress = Instance.MapUniqueAddress((ulong)TotalBytes, MemoryProtection.ReadWrite);
            if (BitsAddress == 0)
            {
                Instance.WinHelper.FreeGdiHandle(Handle);
                return 0;
            }

            GetState(Instance).Bitmaps[Handle] = new Win32kBitmap
            {
                Width = Width,
                Height = Height,
                Planes = Planes,
                BitsPerPixel = BitsPerPixel,
                Stride = Stride,
                BitsAddress = BitsAddress,
                BitsSize = (uint)TotalBytes,
                DibSection = DibSection,
                TopDown = TopDown,
            };
            return Handle;
        }

        internal static bool CopyBitmapBitsIn(BinaryEmulator Instance, in Win32kBitmap Bitmap, ulong SourceAddress)
        {
            if (SourceAddress == 0 || !Instance.IsRegionMapped(SourceAddress, Bitmap.BitsSize))
                return false;

            Span<byte> Chunk = Instance.WinHelper.Shared.GetSpan(BitmapCopyChunkBytes);
            for (uint Copied = 0; Copied < Bitmap.BitsSize;)
            {
                int Size = (int)Math.Min(BitmapCopyChunkBytes, Bitmap.BitsSize - Copied);
                Span<byte> Slice = Chunk.Slice(0, Size);
                if (!Instance.ReadMemory(SourceAddress + Copied, Slice, (uint)Size))
                    return false;

                if (!Instance.WriteMemory(Bitmap.BitsAddress + Copied, Slice))
                    return false;

                Copied += (uint)Size;
            }

            return true;
        }

        internal static bool TryGetBitmap(BinaryEmulator Instance, ulong Handle, out Win32kBitmap Bitmap)
        {
            if (Handle != 0)
                return GetState(Instance).Bitmaps.TryGetValue(Handle, out Bitmap);

            Bitmap = default;
            return false;
        }

        internal static bool RemoveBitmap(BinaryEmulator Instance, ulong Handle)
        {
            Win32kState State = GetState(Instance);
            if (!State.Bitmaps.Remove(Handle, out Win32kBitmap Bitmap))
                return false;

            Instance.UnmapMemoryRegion(Bitmap.BitsAddress);
            return true;
        }

        internal const int TextMetricWSize = 60;

        internal static TextMetricsData DefaultTextMetrics => new TextMetricsData
        {
            Height = 16,
            Ascent = 12,
            Descent = 4,
            AveCharWidth = 8,
            MaxCharWidth = 16,
            Weight = 400,
            DigitizedAspectX = 96,
            DigitizedAspectY = 96,
            FirstChar = 0x20,
            LastChar = 0xFF,
            DefaultChar = 0x20,
            BreakChar = 0x20,
            PitchAndFamily = 0x01,
        };

        internal static void WriteTextMetricsW(Span<byte> Buffer, in TextMetricsData Metrics)
        {
            Buffer.Slice(0, TextMetricWSize).Clear();
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x00, 4), Metrics.Height);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), Metrics.Ascent);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x08, 4), Metrics.Descent);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x0C, 4), Metrics.InternalLeading);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x10, 4), Metrics.ExternalLeading);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x14, 4), Metrics.AveCharWidth);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x18, 4), Metrics.MaxCharWidth);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x1C, 4), Metrics.Weight);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x20, 4), Metrics.Overhang);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x24, 4), Metrics.DigitizedAspectX);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x28, 4), Metrics.DigitizedAspectY);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x2C, 2), Metrics.FirstChar);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x2E, 2), Metrics.LastChar);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x30, 2), Metrics.DefaultChar);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x32, 2), Metrics.BreakChar);
            Buffer[0x34] = Metrics.Italic;
            Buffer[0x35] = Metrics.Underlined;
            Buffer[0x36] = Metrics.StruckOut;
            Buffer[0x37] = Metrics.PitchAndFamily;
            Buffer[0x38] = Metrics.CharSet;
        }

        internal static bool PostMessage(BinaryEmulator Instance, ulong Hwnd, uint Message, ulong WParam, ulong LParam)
        {
            return PostMessage(Instance, GetState(Instance), Hwnd, Message, WParam, LParam);
        }

        private static bool PostMessage(BinaryEmulator Instance, Win32kState State, ulong Hwnd, uint Message, ulong WParam, ulong LParam)
        {
            uint Time = unchecked((uint)Instance.EmulatedTickCount64);

            if (Hwnd == HWND_BROADCAST)
            {
                foreach (ulong TargetHwnd in Instance.WinHelper.TopLevelWindows)
                {
                    if (Instance.WinHelper.GetWindow(TargetHwnd) == null)
                        continue;

                    State.MessageQueue.Enqueue(new Win32kMessage(TargetHwnd, Message, WParam, LParam, Time, 0, 0));
                    NoteQueuedMessage(State, Message);
                }

                Instance.WakeSignal.Bump();
                return true;
            }

            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
                return false;

            // A window never holds more than one WM_PAINT.
            if (Message == WM_PAINT && IsQueued(State, Hwnd, WM_PAINT))
                return true;

            State.MessageQueue.Enqueue(new Win32kMessage(Hwnd, Message, WParam, LParam, Time, 0, 0));
            NoteQueuedMessage(State, Message);
            Instance.WakeSignal.Bump();
            return true;
        }

        private static bool IsQueued(Win32kState State, ulong Hwnd, uint Message)
        {
            foreach (Win32kMessage Queued in State.MessageQueue)
            {
                if (Queued.Message == Message && Queued.Hwnd == Hwnd)
                    return true;
            }

            return false;
        }

        private static void NoteQueuedMessage(Win32kState State, uint Message)
        {
            if (State.QueuedWakeBitsValid)
                State.QueuedWakeBits |= GetMessageWakeBits(Message);
        }

        internal static void PostQuitMessage(BinaryEmulator Instance, ulong ExitCode)
        {
            Win32kState State = GetState(Instance);
            State.QuitExitCode = ExitCode;
            State.QuitPosted = true;
            Instance.WakeSignal.Bump();
        }

        internal static bool TryGetMessage(BinaryEmulator Instance, ulong HwndFilter, uint MinMessage, uint MaxMessage, bool Remove, out Win32kMessage Message)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            int Index = 0;
            foreach (Win32kMessage Candidate in State.MessageQueue)
            {
                if (MatchesFilter(Candidate, HwndFilter, MinMessage, MaxMessage))
                {
                    Message = Candidate;
                    if (Remove)
                    {
                        RemoveMessageAt(State, Index);
                        if (Candidate.Message == WM_INPUT)
                            Win32kRawInput.NoteInputDelivered(Instance, (uint)Candidate.LParam);
                    }
                    return true;
                }

                Index++;
            }

            if (State.QuitPosted)
            {
                Message = new Win32kMessage(0, WM_QUIT, State.QuitExitCode, 0, unchecked((uint)Instance.EmulatedTickCount64), 0, 0);
                if (Remove)
                    State.QuitPosted = false;
                return true;
            }

            Message = default;
            return false;
        }

        internal static bool HasQueuedInputEvent(BinaryEmulator Instance, uint WakeMask)
        {
            return GetQueuedWakeBits(Instance, WakeMask) != 0;
        }

        // For a layout that is not a substitute, both halves of the HKL are the language the KLID ends with.
        internal static uint KeyboardLayoutFromKlid(uint Klid)
        {
            uint Language = Klid & 0xFFFF;
            uint Variant = Klid >> 16;
            return Variant == 0 ? (Language << 16) | Language : ((0xF000u | Variant) << 16) | Language;
        }

        internal static bool TryParseKlid(string Klid, out uint Value)
        {
            return uint.TryParse(Klid, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out Value);
        }

        internal static bool IsInstalledKeyboardLayout(BinaryEmulator Instance, string Klid)
        {
            return !string.IsNullOrEmpty(Klid) && Instance.WinHelper.ResolveRegistryKey(KeyboardLayoutsKey + "\\" + Klid) != null;
        }

        /// <summary>
        /// The layouts loaded for the current user, in the order the Preload list gives them. Held until a
        /// registry change could have rewritten that list.
        /// </summary>
        internal static IReadOnlyList<uint> GetKeyboardLayouts(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            uint Generation = Instance.WinHelper.RegistryGeneration;

            if (State.KeyboardLayouts != null && State.KeyboardLayoutsGeneration == Generation)
                return State.KeyboardLayouts;

            List<uint> Layouts = BuildKeyboardLayouts(Instance);
            State.KeyboardLayouts = Layouts;
            State.KeyboardLayoutsGeneration = Generation;
            return Layouts;
        }

        private static List<uint> BuildKeyboardLayouts(BinaryEmulator Instance)
        {
            List<uint> Layouts = new List<uint>();
            WinRegKey Preload = Instance.WinHelper.ResolveRegistryKey(@"\Registry\User\" + Instance.WinHelper.CurrentUserSid + KeyboardPreloadKey);

            for (int Index = 0; Preload != null; Index++)
            {
                if (!Instance.WinHelper.TryEnumerateRegistryValueFull(Preload, Index, out _, out int Type, out byte[] Data))
                    break;

                if (Type != 1 || Data == null || Data.Length < 2)
                    continue;

                string Klid = Encoding.Unicode.GetString(Data).TrimEnd('\0');
                if (!TryParseKlid(Klid, out uint Value))
                    continue;

                uint Layout = KeyboardLayoutFromKlid(Value);
                if (!Layouts.Contains(Layout))
                    Layouts.Add(Layout);
            }

            return Layouts;
        }

        /// <summary>
        /// Backs <see cref="GetCharAdvanceWidth"/>. Fetched once by a caller that measures a run of characters,
        /// so the per-character path costs an array read.
        /// </summary>
        internal static int[] GetCharAdvanceWidthCache(BinaryEmulator Instance, IntPtr Font)
        {
            Dictionary<IntPtr, int[]> Caches = GetState(Instance).CharAdvanceWidthsByFont;
            if (!Caches.TryGetValue(Font, out int[] Cache))
            {
                Cache = new int[char.MaxValue + 1];
                Caches[Font] = Cache;
            }

            return Cache;
        }

        internal static int GetCharAdvanceWidth(BinaryEmulator Instance, IntPtr Font, int[] Cache, char Character, int FallbackWidth)
        {
            int Cached = Cache[Character];
            if (Cached != 0)
                return Cached - 1;

            if (!Instance.WinHelper.MeasureText(Font, Character.ToString(), out int Measured, out _) || Measured <= 0)
                return FallbackWidth;

            Cache[Character] = Measured + 1;
            return Measured;
        }

        internal static uint GetQueuedWakeBits(BinaryEmulator Instance, uint WakeMask)
        {
            DrainHostEvents(Instance);

            if (WakeMask == 0)
                return 0;

            Win32kState State = GetState(Instance);

            if (!State.QueuedWakeBitsValid)
            {
                uint Queued = 0;
                foreach (Win32kMessage Candidate in State.MessageQueue)
                    Queued |= GetMessageWakeBits(Candidate.Message);

                State.QueuedWakeBits = Queued;
                State.QueuedWakeBitsValid = true;
            }

            uint Bits = State.QuitPosted ? State.QueuedWakeBits | QS_POSTMESSAGE : State.QueuedWakeBits;
            return Bits & WakeMask;
        }

        private static uint GetMessageWakeBits(uint Message)
        {
            switch (Message)
            {
                case WM_PAINT:
                    return QS_PAINT;
                case WM_INPUT:
                    return QS_RAWINPUT;
                case WM_MOUSEMOVE:
                    return QS_MOUSEMOVE;
                case WM_LBUTTONDOWN:
                case WM_LBUTTONUP:
                case WM_RBUTTONDOWN:
                case WM_RBUTTONUP:
                    return QS_MOUSEBUTTON;
                case WM_KEYDOWN:
                case WM_KEYUP:
                case WM_CHAR:
                case WM_SYSKEYDOWN:
                case WM_SYSKEYUP:
                case WM_SYSCHAR:
                    return QS_KEY;
                default:
                    return QS_POSTMESSAGE;
            }
        }

        private static bool Is64(BinaryEmulator Instance) => Instance.WinHelper.PointerSize == 8;

        internal static bool WriteMessage(BinaryEmulator Instance, ulong Address, Win32kMessage Message)
        {
            bool Wide = Is64(Instance);
            int Size = Wide ? MSG64_SIZE : MSG32_SIZE;
            if (Address == 0 || !Instance.IsRegionMapped(Address, (uint)Size))
                return false;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size);
            Buffer.Clear();
            if (Wide)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Message.Hwnd);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), Message.Message);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), Message.WParam);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), Message.LParam);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x20, 4), Message.Time);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x24, 4), Message.X);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x28, 4), Message.Y);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Message.Hwnd);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Message.Message);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), (uint)Message.WParam);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x0C, 4), (uint)Message.LParam);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10, 4), Message.Time);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x14, 4), Message.X);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x18, 4), Message.Y);
            }
            return Instance.WriteMemory(Address, Buffer.Slice(0, Size));
        }

        internal static bool TryReadMessage(BinaryEmulator Instance, ulong Address, out Win32kMessage Message)
        {
            bool Wide = Is64(Instance);
            int Size = Wide ? MSG64_SIZE : MSG32_SIZE;
            Message = default;
            if (Address == 0 || !Instance.IsRegionMapped(Address, (uint)Size))
                return false;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size);
            if (!Instance.ReadMemory(Address, Buffer.Slice(0, Size), (uint)Size))
                return false;

            Message = Wide
                ? new Win32kMessage(
                    BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(0x00, 8)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x08, 4)),
                    BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(0x10, 8)),
                    BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(0x18, 8)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x20, 4)),
                    BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x24, 4)),
                    BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x28, 4)))
                : new Win32kMessage(
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x00, 4)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x04, 4)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x08, 4)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x0C, 4)),
                    BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x10, 4)),
                    BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x14, 4)),
                    BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x18, 4)));
            return true;
        }

        internal static bool WritePaintStruct(BinaryEmulator Instance, ulong PaintStructPtr, ulong Hdc, WinWindow Window)
        {
            bool Wide = Is64(Instance);
            int Size = Wide ? PAINTSTRUCT64_SIZE : PAINTSTRUCT32_SIZE;
            if (PaintStructPtr == 0 || !Instance.IsRegionMapped(PaintStructPtr, (uint)Size))
                return false;

            int RectOffset = Wide ? 0x0C : 0x08;
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size);
            Buffer.Clear();
            if (Wide)
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Hdc);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Hdc);

            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset - 4, 4), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 0, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 4, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 8, 4), (int)Math.Min(Window.Width, (uint)int.MaxValue));
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 12, 4), (int)Math.Min(Window.Height, (uint)int.MaxValue));
            return Instance.WriteMemory(PaintStructPtr, Buffer.Slice(0, Size));
        }

        /// <summary>
        /// Reads a UNICODE_STRING in the layout of the guest architecture.
        /// </summary>
        internal static string ReadUnicodeString(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0)
                return null;

            return Instance.WinHelper.TryReadUnicodeString(Address, out string Value, out _) ? Value : null;
        }

        /// <summary>
        /// Reads a LARGE_STRING in the layout of the guest architecture. The high bit of MaximumLength selects ANSI.
        /// </summary>
        internal static string ReadLargeString(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0 || Address <= 0xFFFF)
                return null;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (!Instance.IsRegionMapped(Address, 8 + PointerSize))
                return null;

            uint Length = Instance._emulator.ReadMemoryUInt(Address) & 0x7FFFFFFF;
            uint MaximumLength = Instance._emulator.ReadMemoryUInt(Address + 4);
            ulong Buffer = Instance.WinHelper.ReadPointer(Address + 8);

            if (Buffer == 0 || Length == 0)
                return string.Empty;

            if (!Instance.IsRegionMapped(Buffer, Length))
                return null;

            Encoding Enc = (MaximumLength & 0x80000000u) != 0 ? Encoding.ASCII : Encoding.Unicode;
            return Instance._emulator.ReadMemoryString(Buffer, (int)Length, Enc)?.TrimEnd('\0');
        }

        internal static uint WindowClassSize(BinaryEmulator Instance) => 16 + 8 * (uint)Instance.WinHelper.PointerSize;

        /// <summary>
        /// Reads a WNDCLASSEXW in the layout of the guest architecture.
        /// </summary>
        internal static bool TryReadWindowClass(BinaryEmulator Instance, ulong Address, out Win32kWindowClassDefinition Class)
        {
            Class = default;
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (Address == 0 || !Instance.IsRegionMapped(Address, WindowClassSize(Instance)))
                return false;

            Class.cbSize = Instance._emulator.ReadMemoryUInt(Address + 0);
            Class.style = Instance._emulator.ReadMemoryUInt(Address + 4);
            Class.lpfnWndProc = Instance.WinHelper.ReadPointer(Address + 8);
            Class.cbClsExtra = (int)Instance._emulator.ReadMemoryUInt(Address + 8 + PointerSize);
            Class.cbWndExtra = (int)Instance._emulator.ReadMemoryUInt(Address + 12 + PointerSize);
            Class.hInstance = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize);
            Class.hIcon = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize * 2);
            Class.hCursor = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize * 3);
            Class.hbrBackground = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize * 4);
            Class.lpszMenuName = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize * 5);
            Class.lpszClassName = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize * 6);
            Class.hIconSm = Instance.WinHelper.ReadPointer(Address + 16 + PointerSize * 7);
            return true;
        }

        internal static ulong DispatchMessage(BinaryEmulator Instance, Win32kMessage Message)
        {
            WinWindow Window = Message.Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Message.Hwnd);
            if (Message.Hwnd != 0 && Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                return 0;
            }

            if (Window == null)
                return 0;

            return DefaultWindowProc(Instance, Window, Message.Message, Message.WParam, Message.LParam, false);
        }

        private const int MaxHostInputEventsPerDrain = 64;

        private static void DrainHostEvents(BinaryEmulator Instance)
        {
            ulong Foreground = Instance.WinHelper.GetForegroundWindow();

            // Nothing can be delivered before the guest makes a window visible, and the host queue must survive
            // until then: consuming the repaint flag (or draining input) here would discard the only events a
            // thread parked in MsgWaitForMultipleObjectsEx can ever be woken by.
            if (Foreground == 0)
                return;

            SyncActivation(Instance, Foreground);

            Win32kDpi.DrainHostDpiChange(Instance);

            // The host surface holds no backing store, so a host repaint has erased every control with it.
            if (HostEventQueue.ConsumeRepaint())
            {
                InvalidateWindowTree(Instance, Foreground);
                Instance.WinHelper.PresentDesktop();
            }

            Win32kState State = GetState(Instance);
            bool GeometryChanged = false;
            for (int i = 0; i < MaxHostInputEventsPerDrain; i++)
            {
                if (!HostEventQueue.TryDequeue(out uint Message, out ulong WParam, out ulong LParam))
                    break;

                if (Message == HostEventQueue.RawMouseMotion)
                {
                    Win32kRawInput.DeliverHostRawMouse(Instance, Foreground, unchecked((int)(uint)WParam), unchecked((int)(uint)LParam));
                    continue;
                }

                if (Message >= WM_MOUSEMOVE && Message <= WM_RBUTTONUP)
                {
                    State.CursorX = (short)(LParam & 0xFFFF);
                    State.CursorY = (short)((LParam >> 16) & 0xFFFF);

                    if (State.CursorHiddenWhileTyping)
                    {
                        State.CursorHiddenWhileTyping = false;
                        ApplyCursorVisibility(Instance, State);
                    }
                }
                else if (Message == WM_SIZE)
                {
                    ApplyHostResize(Instance, Foreground, WParam, LParam);
                    GeometryChanged = true;
                }
                else if (Message == WM_MOVE)
                {
                    ApplyHostMove(Instance, Foreground, LParam);
                    GeometryChanged = true;
                }

                if (Win32kRawInput.DeliverHostEvent(Instance, Foreground, Message, WParam, LParam))
                    PostMessage(Instance, ResolveInputTarget(Instance, Foreground, Message, ref LParam), Message, WParam, LParam);
            }

            if (GeometryChanged)
            {
                WinWindow Resized = Instance.WinHelper.GetWindow(Foreground);
                if (Resized != null)
                    Resized.PendingWindowPosChanged = true;
            }
        }

        private static ulong ResolveInputTarget(BinaryEmulator Instance, ulong Foreground, uint Message, ref ulong LParam)
        {
            if (Message >= WM_KEYDOWN && Message <= WM_SYSCHAR)
            {
                ulong Focus = Instance.WinHelper.FocusWindow;
                return Focus != 0 && Instance.WinHelper.GetWindow(Focus) != null ? Focus : Foreground;
            }

            if (Message < WM_MOUSEMOVE || Message > WM_RBUTTONUP)
                return Foreground;

            int X = (short)(LParam & 0xFFFF);
            int Y = (short)((LParam >> 16) & 0xFFFF);

            ulong Capture = GetCaptureWindow(Instance);
            ulong Target = Capture != 0 && Instance.WinHelper.GetWindow(Capture) != null
                ? Capture
                : ChildFromPoint(Instance, Foreground, X, Y, 0);

            if (Target == Foreground)
                return Foreground;

            Instance.WinHelper.GetSurfaceOrigin(Target, out int OffsetX, out int OffsetY);
            LParam = (ulong)(uint)(((Y - OffsetY) << 16) | ((X - OffsetX) & 0xFFFF));
            return Target;
        }

        private const uint WindowStyleDisabled = 0x08000000;

        // X and Y are client coordinates of the top level window, which is the surface every child sits on.
        private static ulong ChildFromPoint(BinaryEmulator Instance, ulong Hwnd, int X, int Y, int Depth)
        {
            if (Depth >= MaxWindowTreeDepth)
                return Hwnd;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Hwnd;

            for (int i = Window.Children.Count - 1; i >= 0; i--)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(Window.Children[i]);
                if (Child == null || !Child.Visible || (Child.Style & WindowStyleDisabled) != 0)
                    continue;

                Instance.WinHelper.GetSurfaceOrigin(Child.Hwnd, out int ChildX, out int ChildY);
                if (X < ChildX || Y < ChildY || X >= ChildX + (int)Child.Width || Y >= ChildY + (int)Child.Height)
                    continue;

                return ChildFromPoint(Instance, Child.Hwnd, X, Y, Depth + 1);
            }

            return Hwnd;
        }

        /// <summary>
        /// Hands activation to the foreground window. A window that never gets WM_ACTIVATE and WM_SETFOCUS is not
        /// the focus window as far as its own toolkit is concerned, and toolkits drop raw input on that test.
        /// </summary>
        private static void SyncActivation(BinaryEmulator Instance, ulong Foreground)
        {
            Win32kState State = GetState(Instance);
            if (State.ActivatedWindow == Foreground)
                return;

            ulong Previous = State.ActivatedWindow;
            State.ActivatedWindow = Foreground;

            if (Previous != 0 && Instance.WinHelper.GetWindow(Previous) != null)
            {
                PostMessage(Instance, Previous, WM_ACTIVATE, WA_INACTIVE, Foreground);
                PostMessage(Instance, Previous, WM_KILLFOCUS, Foreground, 0);
            }

            Instance.WinHelper.ActiveWindow = Foreground;
            Instance.WinHelper.FocusWindow = Foreground;

            if (Previous == 0)
                PostMessage(Instance, Foreground, WM_ACTIVATEAPP, 1, 0);

            PostMessage(Instance, Foreground, WM_ACTIVATE, WA_ACTIVE, Previous);
            PostMessage(Instance, Foreground, WM_SETFOCUS, Previous, 0);
        }

        internal static bool TryDeliverWindowPosChanged(BinaryEmulator Instance, ulong SyscallResult)
        {
            ulong Hwnd = Instance.WinHelper.GetForegroundWindow();
            if (Hwnd == 0)
                return false;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || !Window.PendingWindowPosChanged || Window.WndProc == 0)
                return false;

            ulong WindowPos = Instance.WinHelper.EnsureWindowPosStruct(Window);
            if (WindowPos == 0)
            {
                Window.PendingWindowPosChanged = false;
                return false;
            }

            if (!Instance.WinHelper.BeginGuestCall(Window.WndProc, Hwnd, WM_WINDOWPOSCHANGED, 0, WindowPos, SyscallResult))
                return false;

            Window.PendingWindowPosChanged = false;
            return true;
        }

        private static void ApplyHostMove(BinaryEmulator Instance, ulong Hwnd, ulong LParam)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return;

            Window.X = (short)(LParam & 0xFFFF);
            Window.Y = (short)((LParam >> 16) & 0xFFFF);
            Instance.WinHelper.MaterializeUserWindow(Window);
        }

        private static void ApplyHostResize(BinaryEmulator Instance, ulong Hwnd, ulong WParam, ulong LParam)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return;

            uint Width = (uint)(LParam & 0xFFFF);
            uint Height = (uint)((LParam >> 16) & 0xFFFF);

            // A frame with no client area is iconic whatever it calls itself, and its restore size has to survive:
            // only the client rectangle the guest reads back collapses, so the size pushed back at the host on the
            // next present is still the one to restore to.
            Window.Minimized = WParam == SIZE_MINIMIZED || Width == 0 || Height == 0;
            Window.Maximized = WParam == SIZE_MAXIMIZED;

            if (!Window.Minimized)
            {
                Window.Width = Width;
                Window.Height = Height;
            }

            Window.Dirty = true;
            Instance.WinHelper.MaterializeUserWindow(Window);
        }

        /// <summary>
        /// Screen position of the pointer, tracked from the client-relative coordinates the host window manager
        /// reports for the foreground window.
        /// </summary>
        internal static void GetCursorPosition(BinaryEmulator Instance, out int X, out int Y)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            X = State.CursorX;
            Y = State.CursorY;

            WinWindow Foreground = Instance.WinHelper.GetWindow(Instance.WinHelper.GetForegroundWindow());
            if (Foreground == null)
                return;

            X += Foreground.X;
            Y += Foreground.Y;
        }

        internal static void SetCursorPosition(BinaryEmulator Instance, int X, int Y)
        {
            DrainHostEvents(Instance);

            WinWindow Foreground = Instance.WinHelper.GetWindow(Instance.WinHelper.GetForegroundWindow());
            int ClientX = Foreground == null ? X : X - Foreground.X;
            int ClientY = Foreground == null ? Y : Y - Foreground.Y;

            Win32kState State = GetState(Instance);
            State.CursorX = ClientX;
            State.CursorY = ClientY;

            Instance.WinHelper.WarpHostCursor(ClientX, ClientY);
            Win32kRawInput.ResetPointerBaseline(Instance, ClientX, ClientY);
        }

        /// <summary>
        /// Hands out the one handle every stock cursor resolves to. The shape is the host's, but a guest that asks
        /// for a stock cursor has to get something other than NULL back: NULL is how it says "no cursor".
        /// </summary>
        internal static ulong EnsureStockCursor(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            if (State.StockCursor == 0)
                State.StockCursor = Instance.WinHelper.AllocateUserHandle();

            return State.StockCursor;
        }

        internal static ulong SetCursorHandle(BinaryEmulator Instance, ulong Handle)
        {
            Win32kState State = GetState(Instance);
            ulong Previous = State.CursorAssigned ? State.CursorHandle : EnsureStockCursor(Instance);

            State.CursorHandle = Handle;
            State.CursorAssigned = true;
            ApplyCursorVisibility(Instance, State);
            return Previous;
        }

        internal static int ShowCursor(BinaryEmulator Instance, bool Show)
        {
            Win32kState State = GetState(Instance);
            State.CursorShowCount += Show ? 1 : -1;
            ApplyCursorVisibility(Instance, State);
            return State.CursorShowCount;
        }

        // Separate from the ShowCursor count, so the two cannot cancel each other out.
        internal static void HideCursorWhileTyping(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            State.CursorHiddenWhileTyping = true;
            ApplyCursorVisibility(Instance, State);
        }

        private static void ApplyCursorVisibility(BinaryEmulator Instance, Win32kState State)
        {
            bool Hidden = State.CursorShowCount < 0 || State.CursorHiddenWhileTyping ||
                (State.CursorAssigned && State.CursorHandle == 0);
            if (State.CursorHidden == Hidden)
                return;

            State.CursorHidden = Hidden;
            Instance.WinHelper.SetHostCursorVisible(!Hidden);
        }

        internal static bool InvalidateWindow(BinaryEmulator Instance, ulong Hwnd)
        {
            if (Hwnd == 0)
            {
                foreach (ulong TopLevelHwnd in Instance.WinHelper.TopLevelWindows)
                {
                    WinWindow TopLevel = Instance.WinHelper.GetWindow(TopLevelHwnd);
                    if (TopLevel != null)
                    {
                        TopLevel.Dirty = true;
                        PostMessage(Instance, TopLevel.Hwnd, WM_PAINT, 0, 0);
                    }
                }

                Instance.WinHelper.PresentDesktop();
                return true;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return false;

            Window.Dirty = true;
            PostMessage(Instance, Hwnd, WM_PAINT, 0, 0);
            Instance.WinHelper.PresentDesktop();
            return true;
        }

        internal static void InvalidateWindowTree(BinaryEmulator Instance, ulong Hwnd)
        {
            InvalidateWindowTree(Instance, GetState(Instance), Hwnd, 0);
        }

        private static void InvalidateWindowTree(BinaryEmulator Instance, Win32kState State, ulong Hwnd, int Depth)
        {
            // A child list that has been closed into a loop would otherwise walk forever.
            if (Depth >= MaxWindowTreeDepth)
                return;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || !Window.Visible)
                return;

            Window.Dirty = true;
            PostMessage(Instance, State, Hwnd, WM_PAINT, 0, 0);

            for (int i = 0; i < Window.Children.Count; i++)
                InvalidateWindowTree(Instance, State, Window.Children[i], Depth + 1);
        }

        private const int MaxWindowTreeDepth = 64;

        // The plain callback shape passes hwnd, message, wParam and lParam unchanged. The
        // DispatchMessage-shaped entry beside it carries no lParam, only a pointer to the MSG.
        private const uint WindowProcCallbackIndex = 2;
        private const ulong WindowProcArgumentReserve = 0x400;
        private const int WindowProcArgumentHeaderSize = 0x30;
        private const int WindowProcArgumentBlockSize = 0x40;
        private const int CreateStructSize = 0x50;
        private const int CreateStructNameChars = 96;

        // The syscall in progress does not answer. The procedure's result becomes its return value.
        internal static bool InvokeWindowProc(BinaryEmulator Instance, ulong Hwnd, ulong WndProc, uint Message, ulong WParam, ulong LParam, WinWindowCreation Creation = null, ulong SyscallRetryRip = 0)
        {
            if (!TryBeginWindowProcCallback(Instance, WndProc, out ulong Callback, out ulong ArgumentBuffer))
                return false;

            WriteWindowProcCallbackArguments(Instance, ArgumentBuffer, Hwnd, WndProc, Message, WParam, LParam);
            return Instance.WinHelper.EnterUserCallback(Callback, WindowProcCallbackIndex, ArgumentBuffer, Creation, SyscallRetryRip);
        }

        internal static bool SendWindowCreateMessage(BinaryEmulator Instance, WinWindow Window, uint Message, WinWindowCreation Creation)
        {
            if (Window == null || !TryBeginWindowProcCallback(Instance, Window.WndProc, out ulong Callback, out ulong ArgumentBuffer))
                return false;

            ulong CreateStruct = ArgumentBuffer + WindowProcArgumentHeaderSize;
            ulong NameAddress = CreateStruct + CreateStructSize;
            ulong ClassAddress = NameAddress + (ulong)CreateStructNameChars * 2;

            if (!WriteCallbackString(Instance, NameAddress, Window.Title))
                NameAddress = 0;

            // A class named by atom stays an atom, the way CreateWindowEx was called.
            if (Window.ClassAtom != 0 && Window.ClassName != null && Window.ClassName.StartsWith("#ATOM_", StringComparison.Ordinal))
                ClassAddress = Window.ClassAtom;
            else if (!WriteCallbackString(Instance, ClassAddress, Window.ClassName))
                ClassAddress = 0;

            Span<byte> Data = Instance.WinHelper.Shared.GetSpan(CreateStructSize).Slice(0, CreateStructSize);
            Data.Clear();

            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Window.CreateParam);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Window.InstanceHandle);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Window.MenuHandle);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x18, 8), Window.ParentHwnd);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x20, 4), Window.Height);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x24, 4), Window.Width);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x28, 4), (uint)Window.Y);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x2C, 4), (uint)Window.X);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x30, 4), Window.Style);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x38, 8), NameAddress);
            BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x40, 8), ClassAddress);
            BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x48, 4), Window.ExStyle);

            if (!Instance.WriteMemory(CreateStruct, Data))
                return false;

            WriteWindowProcCallbackArguments(Instance, ArgumentBuffer, Window.Hwnd, Window.WndProc, Message, 0, CreateStruct);
            return Instance.WinHelper.EnterUserCallback(Callback, WindowProcCallbackIndex, ArgumentBuffer, Creation);
        }

        private static bool TryBeginWindowProcCallback(BinaryEmulator Instance, ulong WndProc, out ulong Callback, out ulong ArgumentBuffer)
        {
            Callback = 0;
            ArgumentBuffer = 0;

            if (WndProc == 0 || Instance.WinHelper.PointerSize != 8)
                return false;

            Callback = Instance.WinHelper.GetKernelCallbackEntry(WindowProcCallbackIndex);
            if (Callback == 0)
                return false;

            ulong CurrentRsp = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
            if (!Instance.IsRegionMapped(CurrentRsp, 8))
                return false;

            ArgumentBuffer = (CurrentRsp - WindowProcArgumentReserve) & ~0xFUL;
            if (!Instance.IsRegionMapped(ArgumentBuffer, WindowProcArgumentReserve))
                return false;

            for (int Offset = 0; Offset < WindowProcArgumentBlockSize; Offset += 8)
                Instance._emulator.WriteMemory(ArgumentBuffer + (ulong)Offset, 0UL, 8);

            return true;
        }

        private static void WriteWindowProcCallbackArguments(BinaryEmulator Instance, ulong ArgumentBuffer,
            ulong Hwnd, ulong WndProc, uint Message, ulong WParam, ulong LParam)
        {
            Instance._emulator.WriteMemory(ArgumentBuffer + 0x00, Hwnd, 8);
            Instance._emulator.WriteMemory(ArgumentBuffer + 0x08, (ulong)Message, 8);
            Instance._emulator.WriteMemory(ArgumentBuffer + 0x10, WParam, 8);
            Instance._emulator.WriteMemory(ArgumentBuffer + 0x18, LParam, 8);
            Instance._emulator.WriteMemory(ArgumentBuffer + 0x20, 0UL, 8);
            Instance._emulator.WriteMemory(ArgumentBuffer + 0x28, WndProc, 8);
        }

        private static bool WriteCallbackString(BinaryEmulator Instance, ulong Address, string Value)
        {
            string Text = Value ?? string.Empty;
            if (Text.Length >= CreateStructNameChars)
                Text = Text.Substring(0, CreateStructNameChars - 1);

            uint Bytes = (uint)((Text.Length + 1) * 2);
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Bytes).Slice(0, (int)Bytes);
            Buffer.Clear();
            Encoding.Unicode.GetBytes(Text, Buffer);

            return Instance.WriteMemory(Address, Buffer);
        }

        internal static ulong HandleMessageCall(BinaryEmulator Instance, ulong Hwnd, uint Message, ulong WParam, ulong LParam, bool Ansi)
        {
            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                return 0;
            }

            WinWindow Window = Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return 0;

            return DefaultWindowProc(Instance, Window, Message, WParam, LParam, Ansi);
        }

        private static ulong DefaultWindowProc(BinaryEmulator Instance, WinWindow Window, uint Message, ulong WParam, ulong LParam, bool Ansi)
        {
            switch (Message)
            {
                case WM_SETTEXT:
                    Window.Title = ReadWindowTextPointer(Instance, LParam, Ansi) ?? string.Empty;
                    Window.Dirty = true;
                    Instance.WinHelper.MaterializeUserWindow(Window);
                    Instance.WinHelper.PresentDesktop();
                    return 1;

                case WM_GETTEXT:
                    return WriteWindowText(Instance, Window.Title ?? string.Empty, LParam, WParam, Ansi);

                case WM_GETTEXTLENGTH:
                    return (ulong)(Window.Title?.Length ?? 0);

                case WM_NCHITTEST:
                    return HTCLIENT;

                // DefWindowProc accepts the window. Answering zero here would refuse every creation.
                case WM_NCCREATE:
                    return 1;

                case WM_ERASEBKGND:
                    return EraseWindowBackground(Instance, Window, WParam) ? 1ul : 0ul;

                case WM_CLOSE:
                    Instance.WinHelper.DestroyWindow(Window.Hwnd);
                    return 0;

                default:
                    if (Message >= WM_CTLCOLORMSGBOX && Message <= WM_CTLCOLORSTATIC)
                        return Instance.WinHelper.GetSystemColorBrush(DefaultControlColorIndex(Message));

                    return 0;
            }
        }

        private static bool EraseWindowBackground(BinaryEmulator Instance, WinWindow Window, ulong Hdc)
        {
            WinWindowClass Class = Window.ClassAtom == 0 ? null : Instance.WinHelper.GetWindowClass(Window.ClassAtom);
            ulong Background = Class?.BackgroundBrush ?? 0;
            if (Background == 0)
                return false;

            // A class can name a system colour instead of a brush, as the colour index plus one.
            uint Color = Background <= SystemColorCount
                ? Instance.WinHelper.GetSystemColor((int)Background - 1)
                : ResolvePenBrush(Instance, Background, false).ColorRef;

            Instance.WinHelper.EnqueueGdiFillRect(Window.Hwnd, Hdc, 0, 0,
                (int)Window.Width, (int)Window.Height, Color, PatCopy);
            return true;
        }

        private const uint SystemColorCount = 31;
        private const uint PatCopy = 0x00F00021;

        internal static int DefaultControlColorIndex(uint Message)
        {
            switch (Message)
            {
                case WM_CTLCOLOREDIT:
                case WM_CTLCOLORLISTBOX:
                    return COLOR_WINDOW;

                case WM_CTLCOLORSCROLLBAR:
                    return COLOR_SCROLLBAR;

                default:
                    return COLOR_BTNFACE;
            }
        }

        internal static bool RemoveFlagSet(uint Flags)
        {
            return (Flags & PM_REMOVE) != 0;
        }

        private static bool MatchesFilter(Win32kMessage Message, ulong HwndFilter, uint MinMessage, uint MaxMessage)
        {
            if (HwndFilter != 0 && Message.Hwnd != HwndFilter)
                return false;

            if (MinMessage == 0 && MaxMessage == 0)
                return true;

            return Message.Message >= MinMessage && Message.Message <= MaxMessage;
        }

        private static void RemoveMessageAt(Win32kState State, int Index)
        {
            Queue<Win32kMessage> Queue = State.MessageQueue;
            int Count = Queue.Count;
            for (int i = 0; i < Count; i++)
            {
                Win32kMessage Message = Queue.Dequeue();
                if (i != Index)
                    Queue.Enqueue(Message);
            }

            State.QueuedWakeBitsValid = false;
        }

        private static string ReadWindowTextPointer(BinaryEmulator Instance, ulong Address, bool Ansi)
        {
            if (Address == 0)
                return null;

            Encoding Encoding = Ansi ? Encoding.ASCII : Encoding.Unicode;
            return Instance._emulator.ReadMemoryString(Address, MaxWindowTextBytes, Encoding)?.TrimEnd('\0');
        }

        private static ulong WriteWindowText(BinaryEmulator Instance, string Text, ulong BufferAddress, ulong CapacityCharacters, bool Ansi)
        {
            if (BufferAddress == 0 || CapacityCharacters == 0)
                return 0;

            ulong MaxCharacters = CapacityCharacters - 1;
            string Output = Text.Length > (int)Math.Min(MaxCharacters, (ulong)int.MaxValue) ? Text.Substring(0, (int)Math.Min(MaxCharacters, (ulong)int.MaxValue)) : Text;
            Encoding Encoding = Ansi ? Encoding.ASCII : Encoding.Unicode;
            int TerminatorBytes = Ansi ? 1 : 2;
            int ByteCount = Encoding.GetByteCount(Output);
            ulong RequiredBytes = (ulong)(ByteCount + TerminatorBytes);

            if (!Instance.IsRegionMapped(BufferAddress, RequiredBytes))
                return 0;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredBytes);
            Buffer.Slice(0, (int)RequiredBytes).Clear();
            Encoding.GetBytes(Output, Buffer.Slice(0, ByteCount));
            if (!Instance.WriteMemory(BufferAddress, Buffer.Slice(0, (int)RequiredBytes)))
                return 0;

            return (ulong)Output.Length;
        }

        internal const ushort FnidFirst = 0x029A;
        internal const ushort FnidScrollBar = 0x029A;
        internal const ushort FnidIconTitle = 0x029B;
        internal const ushort FnidMenu = 0x029C;
        internal const ushort FnidDesktop = 0x029D;
        internal const ushort FnidDefWindowProc = 0x029E;
        internal const ushort FnidMessageWnd = 0x029F;
        internal const ushort FnidSwitch = 0x02A0;
        internal const ushort FnidButton = 0x02A1;
        internal const ushort FnidComboBox = 0x02A2;
        internal const ushort FnidComboLBox = 0x02A3;
        internal const ushort FnidDialog = 0x02A4;
        internal const ushort FnidEdit = 0x02A5;
        internal const ushort FnidListBox = 0x02A6;
        internal const ushort FnidMdiClient = 0x02A7;
        internal const ushort FnidStatic = 0x02A8;
        internal const ushort FnidIme = 0x02A9;
        internal const ushort FnidGhost = 0x02AA;

        private const ushort FnidSendMessageFirst = 0x02B1;
        private const ushort FnidSendMessageLast = 0x02B8;
        internal const ushort FnidLast = FnidSendMessageLast;
        internal const int FnidCount = FnidLast - FnidFirst + 1;

        // FNID_DDEML, FNID_DESTROY and FNID_FREED ride above the fnid itself.
        private const uint FnidStatusBits = 0xE000;

        // A dialog template names a standard control by an ordinal into gpsi->atomSysClass.
        private const int IclsButton = 0;
        private const int IclsEdit = 1;
        private const int IclsStatic = 2;
        private const int IclsListBox = 3;
        private const int IclsScrollBar = 4;
        private const int IclsComboBox = 5;
        private const int IclsMdiClient = 6;
        private const int IclsComboLBox = 7;
        private const int IclsIme = 15;
        private const int IclsGhost = 16;
        private const int IclsDesktop = 17;
        private const int IclsDialog = 18;
        private const int IclsMenu = 19;
        private const int IclsSwitch = 20;
        private const int IclsIconTitle = 21;

        internal static bool IsSendMessageFunction(uint FunctionId)
        {
            ushort Fnid = MaskFunctionId(FunctionId);
            return Fnid >= FnidSendMessageFirst && Fnid <= FnidSendMessageLast;
        }

        internal static ushort MaskFunctionId(uint FunctionId)
        {
            return (ushort)(FunctionId & ~FnidStatusBits);
        }

        // A control reads a sibling's class atom out of gpsi->atomSysClass once, so every slot has to answer
        // before user32 registers anything. The five named by an integer atom keep it.
        internal static readonly (ushort FunctionId, int Index, ushort WellKnownAtom, string Name)[] ReservedClasses =
        {
            (FnidButton, IclsButton, (ushort)0, "Button"),
            (FnidEdit, IclsEdit, (ushort)0, "Edit"),
            (FnidStatic, IclsStatic, (ushort)0, "Static"),
            (FnidListBox, IclsListBox, (ushort)0, "ListBox"),
            (FnidScrollBar, IclsScrollBar, (ushort)0, "ScrollBar"),
            (FnidComboBox, IclsComboBox, (ushort)0, "ComboBox"),
            (FnidMdiClient, IclsMdiClient, (ushort)0, "MDIClient"),
            (FnidComboLBox, IclsComboLBox, (ushort)0, "ComboLBox"),
            (FnidIme, IclsIme, (ushort)0, "IME"),
            (FnidGhost, IclsGhost, (ushort)0, "Ghost"),
            (FnidMenu, IclsMenu, (ushort)32768, "#32768"),
            (FnidDesktop, IclsDesktop, (ushort)32769, "#32769"),
            (FnidDialog, IclsDialog, (ushort)32770, "#32770"),
            (FnidSwitch, IclsSwitch, (ushort)32771, "#32771"),
            (FnidIconTitle, IclsIconTitle, (ushort)32772, "#32772"),
        };

        internal static bool TryGetSystemClassIndex(uint FunctionId, out int Index)
        {
            switch (MaskFunctionId(FunctionId))
            {
                case FnidButton: Index = IclsButton; return true;
                case FnidEdit: Index = IclsEdit; return true;
                case FnidStatic: Index = IclsStatic; return true;
                case FnidListBox: Index = IclsListBox; return true;
                case FnidScrollBar: Index = IclsScrollBar; return true;
                case FnidComboBox: Index = IclsComboBox; return true;
                case FnidMdiClient: Index = IclsMdiClient; return true;
                case FnidComboLBox: Index = IclsComboLBox; return true;
                case FnidIme: Index = IclsIme; return true;
                case FnidGhost: Index = IclsGhost; return true;
                case FnidDesktop: Index = IclsDesktop; return true;
                case FnidDialog: Index = IclsDialog; return true;
                case FnidMenu: Index = IclsMenu; return true;
                case FnidSwitch: Index = IclsSwitch; return true;
                case FnidIconTitle: Index = IclsIconTitle; return true;
                default: Index = -1; return false;
            }
        }

        private const ulong WindowStateBase = 0x10;
        private const int WindowStateExStyleFirstByte = 0x08;
        private const int WindowStateStyleFirstByte = 0x0C;
        private const int WindowStateFieldBytes = 4;
        private const int WindowStateDialogByte = 0x02;
        private const byte WindowStateDialogMask = 0x01;

        // user32 names the byte with a packed word, the high byte is the offset from tagWND+0x10 and
        // the low byte is the mask.
        internal static bool ApplyWindowState(BinaryEmulator Instance, WinWindow Window, uint Packed, bool Set)
        {
            if (Window == null || Window.ClientWindowAddress == 0)
                return false;

            int Offset = (int)((Packed >> 8) & 0xFF);
            byte Mask = (byte)(Packed & 0xFF);
            ulong Address = Window.ClientWindowAddress + WindowStateBase + (ulong)Offset;

            if (!Instance.IsRegionMapped(Address, 1))
                return false;

            byte Current = (byte)Instance.ReadMemoryUInt(Address);
            byte Updated = Set ? (byte)(Current | Mask) : (byte)(Current & ~Mask);
            Instance._emulator.WriteMemory(Address, Updated, 1);

            // The next refresh of the window writes win32k's own copy back over whatever the guest set here.
            if (Offset >= WindowStateStyleFirstByte && Offset < WindowStateStyleFirstByte + WindowStateFieldBytes)
            {
                Window.Style = ReplaceByte(Window.Style, Offset - WindowStateStyleFirstByte, Updated);
                Window.Visible = (Window.Style & WinSysHelper.UserWindowStyleVisible) != 0;
            }
            else if (Offset >= WindowStateExStyleFirstByte && Offset < WindowStateExStyleFirstByte + WindowStateFieldBytes)
            {
                uint Composed = Window.ExStyle | (Window.Visible ? WinSysHelper.UserWindowStateVisible : 0u);
                Composed = ReplaceByte(Composed, Offset - WindowStateExStyleFirstByte, Updated);

                Window.Visible = (Composed & WinSysHelper.UserWindowStateVisible) != 0;
                Window.ExStyle = Composed & ~WinSysHelper.UserWindowStateVisible;
            }
            else if (Offset == WindowStateDialogByte && (Mask & WindowStateDialogMask) != 0)
            {
                Window.IsDialog = (Updated & WindowStateDialogMask) != 0;
            }

            return true;
        }

        private static uint ReplaceByte(uint Value, int Index, byte Replacement)
        {
            int Shift = Index * 8;
            return (Value & ~(0xFFu << Shift)) | ((uint)Replacement << Shift);
        }

        internal static bool TryExchangeWindowExtra(BinaryEmulator Instance, WinWindow Window, int Offset, ulong Value, uint Size, out ulong Previous)
        {
            Previous = 0;

            if (Window == null || Offset < 0 || Offset > Window.WindowExtraBytes - (int)Size)
                return false;

            ulong Extra = Instance.WinHelper.GetWindowExtraBytesAddress(Window);
            if (Extra == 0 || !Instance.IsRegionMapped(Extra + (ulong)Offset, Size))
                return false;

            ulong Address = Extra + (ulong)Offset;
            Previous = Size == 8 ? Instance.ReadMemoryULong(Address) : Instance.ReadMemoryUInt(Address);
            return Instance._emulator.WriteMemory(Address, Value, Size);
        }

        private const int OemGlyphSize = 13;
        private const int OemRadioMask = 71;
        private const int OemCheckBoxFirst = 72;
        private const int OemRadioFirst = 77;
        private const int OemThreeStateFirst = 82;
        private const int OemStatesPerGlyph = 5;
        private const int OemLast = OemThreeStateFirst + OemStatesPerGlyph - 1;

        private const int OemStateChecked = 1;
        private const int OemStatePushed = 2;
        private const int OemStateCheckedPushed = 3;
        private const int OemStateCheckedDisabled = 4;

        internal const int COLOR_WINDOWTEXT = 8;
        internal const int COLOR_BTNSHADOW = 16;
        internal const int COLOR_GRAYTEXT = 17;

        internal static bool TryGetOemBitmapSize(int Index, out int Width, out int Height)
        {
            Width = OemGlyphSize;
            Height = OemGlyphSize;
            return Index >= OemRadioMask && Index <= OemLast;
        }

        // A radio arrives as two blits, a mask under SRCAND then the glyph under SRCINVERT. Drawing the
        // circle once on the second is the same picture.
        internal static bool DrawOemBitmap(BinaryEmulator Instance, ulong Hdc, int X, int Y, int Index)
        {
            if (Index < OemRadioMask || Index > OemLast)
                return false;

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
                return false;

            if (Index == OemRadioMask)
                return true;

            bool Round = Index >= OemRadioFirst && Index < OemThreeStateFirst;
            int First = Round ? OemRadioFirst : Index >= OemThreeStateFirst ? OemThreeStateFirst : OemCheckBoxFirst;
            int State = Index - First;

            bool Marked = State == OemStateChecked || State == OemStateCheckedPushed || State == OemStateCheckedDisabled;
            bool Sunken = State == OemStatePushed || State == OemStateCheckedPushed || State == OemStateCheckedDisabled ||
                Index >= OemThreeStateFirst;

            uint Interior = Instance.WinHelper.GetSystemColor(Sunken ? COLOR_BTNFACE : COLOR_WINDOW);
            uint Border = Instance.WinHelper.GetSystemColor(COLOR_BTNSHADOW);
            uint Mark = Instance.WinHelper.GetSystemColor(State == OemStateCheckedDisabled ? COLOR_GRAYTEXT : COLOR_WINDOWTEXT);

            Instance.WinHelper.EnqueueGdiShape(Hwnd, Hdc, Round ? GdiPrimitiveKind.Ellipse : GdiPrimitiveKind.Rectangle,
                X, Y, X + OemGlyphSize, Y + OemGlyphSize, Border, 1, Interior);

            if (!Marked)
                return true;

            if (Round)
            {
                Instance.WinHelper.EnqueueGdiShape(Hwnd, Hdc, GdiPrimitiveKind.Ellipse,
                    X + 4, Y + 4, X + OemGlyphSize - 4, Y + OemGlyphSize - 4, Mark, 1, Mark);
                return true;
            }

            Instance.WinHelper.EnqueueGdiLine(Hwnd, Hdc, X + 3, Y + 6, X + 5, Y + 9, Mark, 2);
            Instance.WinHelper.EnqueueGdiLine(Hwnd, Hdc, X + 5, Y + 9, X + 10, Y + 3, Mark, 2);
            return true;
        }
    }
}
