using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
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

        // Set only for a thread message, which has no window to name its reader.
        public readonly uint TargetThreadId;

        // A message NT sends, queued here instead.
        public readonly bool Notification;

        public Win32kMessage(ulong Hwnd, uint Message, ulong WParam, ulong LParam, uint Time, int X, int Y, uint TargetThreadId = 0, bool Notification = false)
        {
            this.Hwnd = Hwnd;
            this.Message = Message;
            this.WParam = WParam;
            this.LParam = LParam;
            this.Time = Time;
            this.X = X;
            this.Y = Y;
            this.TargetThreadId = TargetThreadId;
            this.Notification = Notification;
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
        private const uint EtoOpaque = 0x0002;

        private const uint USER_TIMER_MINIMUM = 0x0000000A;
        private const uint USER_TIMER_MAXIMUM = 0x7FFFFFFF;

        internal const uint ERROR_SUCCESS = 0;
        internal const uint ERROR_INVALID_HANDLE = 6;
        internal const uint ERROR_ACCESS_DENIED = 5;
        internal const uint ERROR_INVALID_PARAMETER = 87;
        internal const uint ERROR_INVALID_FLAGS = 1004;
        internal const uint ERROR_INVALID_CURSOR_HANDLE = 1402;
        internal const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
        internal const uint ERROR_INSUFFICIENT_BUFFER = 122;
        internal const uint ERROR_NOACCESS = 998;
        internal const uint ERROR_INVALID_WINDOW_HANDLE = 1400;
        internal const uint ERROR_INCORRECT_SIZE = 1462;
        internal const uint ERROR_CANNOT_FIND_WND_CLASS = 1407;
        internal const uint ERROR_INVALID_THREAD_ID = 1444;

        internal const int MaxClassExtraBytes = 0x10000;

        internal const string KeyboardPreloadKey = @"\Keyboard Layout\Preload";
        internal const string KeyboardLayoutsKey = @"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Keyboard Layouts";

        internal const byte PenHandleType = 0x30;
        internal const byte BrushHandleType = 0x10;
        internal const byte BitmapHandleType = 0x05;
        internal const byte RegionHandleType = 0x04;
        internal const byte FontHandleType = 0x0A;
        internal const byte PaletteHandleType = 0x08;

        internal const uint WM_NULL = 0x0000;
        internal const uint WM_CREATE = 0x0001;
        internal const uint WM_DESTROY = 0x0002;
        internal const uint WM_NCCREATE = 0x0081;
        internal const uint WM_SIZE = 0x0005;
        internal const uint WM_ACTIVATE = 0x0006;
        internal const uint WM_SETFOCUS = 0x0007;
        internal const uint WM_KILLFOCUS = 0x0008;
        internal const uint WM_ACTIVATEAPP = 0x001C;
        internal const uint WM_NCACTIVATE = 0x0086;
        internal const uint WM_MOVE = 0x0003;
        internal const uint WM_WINDOWPOSCHANGING = 0x0046;
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
        internal const uint WM_TIMER = 0x0113;
        internal const uint WM_SETTEXT = 0x000C;
        internal const uint WM_SETREDRAW = 0x000B;
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
        internal const uint WM_MBUTTONDOWN = 0x0207;
        internal const uint WM_MBUTTONUP = 0x0208;
        internal const uint WM_MOUSEWHEEL = 0x020A;
        internal const uint WM_XBUTTONDOWN = 0x020B;
        internal const uint WM_XBUTTONUP = 0x020C;
        internal const uint WM_POINTERUPDATE = 0x0245;
        internal const uint WM_POINTERDOWN = 0x0246;
        internal const uint WM_POINTERUP = 0x0247;
        internal const uint WM_MOUSEHWHEEL = 0x020E;

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
        private const ulong FirstDeferWindowPosHandle = 0x780001;
        private const uint PM_REMOVE = 0x0001;
        private const int MSG64_SIZE = 48;
        private const int MSG32_SIZE = 28;
        private const int PAINTSTRUCT64_SIZE = 72;
        private const int PAINTSTRUCT32_SIZE = 64;
        private const int MaxWindowTextBytes = 0x1000;
        private const long MaxBitmapBytes = 0x40000000;
        private const long MaxBlitPixels = MaxBitmapBytes / 4;
        private const uint BitmapCopyChunkBytes = 0x10000;

        private static readonly ConditionalWeakTable<BinaryEmulator, Win32kState> States = new();

        private sealed class Win32kState
        {
            public readonly Queue<Win32kMessage> MessageQueue = new();
            public readonly List<Win32kTimer> Timers = new();
            public readonly Dictionary<ulong, Win32kCursorIcon> CursorIcons = new();
            public ulong NextWindowlessTimerId = 1;
            public readonly Dictionary<ulong, Win32kDeviceContext> DeviceContexts = new();
            public readonly Dictionary<ulong, Win32kPenBrush> PenBrushObjects = new();
            public readonly Dictionary<ulong, Win32kBitmap> Bitmaps = new();
            public readonly Dictionary<ulong, GdiClipRect[]> RegionRects = new();
            public readonly Dictionary<ulong, Win32kFont> Fonts = new();
            public readonly Dictionary<string, IReadOnlyList<FontFamilyData>> FontFamilies = new();

            // Advance width per character, biased by one so that zero reads as unmeasured.
            public readonly Dictionary<IntPtr, int[]> CharAdvanceWidthsByFont = new();

            public ulong StockBitmap;
            public ulong DisplaySurfaceBitmap;
            public ulong NextDeviceContext = FirstDeviceContextHandle;
            public ulong CaptureWindow;
            public bool QuitPosted;
            public ulong QuitExitCode;

            public int CursorScreenX;
            public int CursorScreenY;

            public ulong LastActiveWindow;

            public readonly Queue<ulong> PendingWindowPosChanged = new();
            public readonly List<Win32kSentNotification> SentNotifications = new();
            public int QueuedNotifications;
            public ulong CursorHandle;
            public ulong UpdateLockWindow;
            public ulong StockCursor;
            public bool CursorAssigned;
            public int CursorShowCount;
            public bool CursorHidden;
            public bool CursorClipped;
            public int ClipLeft;
            public int ClipTop;
            public int ClipRight;
            public int ClipBottom;
            public bool CursorHiddenWhileTyping;
            public bool HostFocused = true;

            // Zero when the key is up, 1 for WM_KEYDOWN, 2 for WM_SYSKEYDOWN.
            public readonly byte[] KeyDownMessage = new byte[256];
            public int KeysHeld;

            // 0x80 held, 0x01 flips on every press. Mouse buttons live here too.
            public readonly byte[] KeyState = new byte[256];
            public readonly byte[] KeyPressedSinceQuery = new byte[256];

            public readonly Dictionary<ulong, List<Win32kDeferredWindowPos>> DeferredWindowPositions = new();
            public ulong NextDeferHandle = FirstDeferWindowPosHandle;

            public Win32kCaret Caret;

            public uint QueuedWakeBits;
            public bool QueuedWakeBitsValid;

            public IReadOnlyList<uint> KeyboardLayouts;
            public uint KeyboardLayoutsGeneration;

            public bool MouseInPointer;
            public uint PointerFlags;
            public uint PointerFrameId;
            public uint PointerButtonChange;
            public int PointerScreenX;
            public int PointerScreenY;
            public ulong PointerTargetHwnd;

            // Scratch lists. Never hold one across a call into the guest.
            public readonly List<GdiClipRect> RedrawArea = new();
            public readonly List<GdiClipRect> InvalidateArea = new();
            public readonly List<GdiClipRect> InvalidateSubtract = new();
            public readonly List<GdiClipRect> UnionPieces = new();

            public readonly List<GdiClipRect> ScrollClip = new();
            public readonly List<GdiClipRect> ScrollSource = new();
            public readonly List<GdiClipRect> ScrollTarget = new();
            public readonly List<GdiClipRect> ScrollValid = new();
            public readonly List<GdiClipRect> ScrollExposed = new();
            public readonly List<GdiClipRect> ScrollWork = new();

            public readonly List<GdiClipRect> RegionA = new();
            public readonly List<GdiClipRect> RegionB = new();
            public readonly List<GdiClipRect> RegionResult = new();

            public readonly List<GdiClipRect> DcArea = new();
            public readonly List<GdiClipRect> DcWork = new();
            public readonly List<GdiClipRect> PaintArea = new();
        }

        internal static void GetRegionScratch(BinaryEmulator Instance, out List<GdiClipRect> A, out List<GdiClipRect> B, out List<GdiClipRect> Result)
        {
            Win32kState State = GetState(Instance);
            A = State.RegionA;
            B = State.RegionB;
            Result = State.RegionResult;
            A.Clear();
            B.Clear();
            Result.Clear();
        }

        internal struct Win32kDeferredWindowPos
        {
            public ulong Hwnd;
            public ulong InsertAfter;
            public int X;
            public int Y;
            public int Width;
            public int Height;
            public uint Flags;
        }

        internal sealed class Win32kCursorIcon
        {
            public ushort ResourceType;
            public ulong MaskBitmap;
            public ulong ColorBitmap;
            public int Width;
            public int Height;
            public int HotspotX;
            public int HotspotY;
            public uint Flags;
            public uint BitsPerPixel;
        }

        private sealed class Win32kTimer
        {
            public ulong Hwnd;
            public ulong Id;
            public ulong Proc;
            public uint Elapse;
            public long Due;
            public uint ThreadId;
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

        private struct Win32kDcState
        {
            public ulong Bitmap;
            public ulong Font;
            public GdiClipRect[] Clip;
            public byte[] Attributes;
        }

        // NT: DC::vCopyTo saves and restores this much of DC_ATTR.
        private const int DcAttributeSaveSize = 0x1B0;

        private sealed class Win32kDeviceContext
        {
            public ulong Handle;
            public ulong Hwnd;
            public bool WindowDc;
            public bool PaintDc;
            public bool Display;
            public ulong SelectedBitmap;
            public ulong SelectedFont;
            public ulong SelectedPalette;
            public List<Win32kDcState> SavedStates;

            // Device coordinates. Null when not set.
            public GdiClipRect[] Clip;
            public GdiClipRect[] PaintArea;

            // Caches, valid while their source arrays are unchanged.
            public GdiClipRect[] CombinedClip;
            public GdiClipRect[] CombinedClipSource;
            public GdiClipRect[] CombinedPaintArea;
            public GdiClipRect[] DrawClip;
            public GdiClipRect[] DrawClipSource;
            public GdiClipRect[] DrawClipVisible;
            public int DrawClipX;
            public int DrawClipY;

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

        internal const uint SwpNoSize = 0x0001;
        internal const uint SwpNoMove = 0x0002;
        internal const uint SwpNoZOrder = 0x0004;
        internal const uint SwpNoRedraw = 0x0008;
        internal const uint SwpNoActivate = 0x0010;
        internal const uint SwpFrameChanged = 0x0020;

        internal static bool ApplyWindowPos(BinaryEmulator Instance, in Win32kDeferredWindowPos Position)
        {
            const uint SWP_NOSIZE = SwpNoSize;
            const uint SWP_NOMOVE = SwpNoMove;
            const uint SWP_NOZORDER = SwpNoZOrder;
            const uint SWP_SHOWWINDOW = 0x0040;
            const uint SWP_HIDEWINDOW = 0x0080;
            const uint WS_VISIBLE = 0x10000000;

            WinWindow Window = Instance.WinHelper.GetWindow(Position.Hwnd);
            if (Window == null)
                return false;

            bool WasVisible = Window.Visible;
            int OldX = Window.X;
            int OldY = Window.Y;
            uint OldWidth = Window.Width;
            uint OldHeight = Window.Height;

            if ((Position.Flags & SWP_NOMOVE) == 0)
            {
                Window.X = Position.X;
                Window.Y = Position.Y;
            }

            if ((Position.Flags & SWP_NOSIZE) == 0)
            {
                Window.Width = (uint)Math.Max(Position.Width, 0);
                Window.Height = (uint)Math.Max(Position.Height, 0);
            }

            if ((Position.Flags & SWP_HIDEWINDOW) != 0)
            {
                Window.Visible = false;
                Window.RedrawDisabled = false;
                Window.Style &= ~WS_VISIBLE;
            }
            else if ((Position.Flags & SWP_SHOWWINDOW) != 0)
            {
                Window.Visible = true;
                Window.RedrawDisabled = false;
                Window.Style |= WS_VISIBLE;
            }

            bool Restacked = false;
            if ((Position.Flags & SWP_NOZORDER) == 0)
            {
                int OldZOrder = Instance.WinHelper.GetZOrderIndex(Window);
                Instance.WinHelper.UpdateWindowZOrder(Position.Hwnd, Position.InsertAfter);
                Restacked = Instance.WinHelper.GetZOrderIndex(Window) != OldZOrder;
            }

            InvalidateAfterWindowPos(Instance, Window, WasVisible, Position.Flags, OldX, OldY, OldWidth, OldHeight, Restacked);

            Instance.WinHelper.MaterializeUserWindow(Window);

            if (Window.ParentHwnd == 0)
            {
                if (WasVisible && !Window.Visible && Window.Hwnd == Instance.WinHelper.ActiveWindow)
                    ActivateNextWindow(Instance, Window);
                else if (Window.Visible && (Position.Flags & SwpNoActivate) == 0 && CanActivateImplicitly(Window))
                    ActivateWindow(Instance, Window, false);
            }

            return true;
        }

        private const uint SwpNoSendChanging = 0x0400;
        private const uint SwpNoClientSize = 0x0800;
        private const uint SwpNoClientMove = 0x1000;
        private const uint SwpNothingChanged = 0x1807;
        private const uint SwpChangeMask = 0x18E7;
        private const int WindowPosStructSize = 0x28;

        // True while a window procedure runs. ContinueWindowPos then finishes the change.
        internal static bool SendWindowPos(BinaryEmulator Instance, in Win32kDeferredWindowPos Position, out bool Success)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Position.Hwnd);
            Success = Window != null;
            if (Window == null)
                return false;

            return SendWindowPos(Instance, Window, new WinWindowPosChange { Position = Position });
        }

        private static bool SendWindowPos(BinaryEmulator Instance, WinWindow Window, WinWindowPosChange Change)
        {
            if ((Change.Position.Flags & SwpNoSendChanging) == 0 && IsOwnedByCurrentThread(Instance, Window)
                && SendWindowPosMessage(Instance, Window, WM_WINDOWPOSCHANGING, Change))
            {
                return true;
            }

            return FinishWindowPos(Instance, Window, Change);
        }

        private static bool SendWindowPositions(BinaryEmulator Instance, List<Win32kDeferredWindowPos> Positions, int Start)
        {
            for (int i = Start; i < Positions.Count; i++)
            {
                WinWindow Window = Instance.WinHelper.GetWindow(Positions[i].Hwnd);
                if (Window != null && SendWindowPos(Instance, Window, new WinWindowPosChange { Position = Positions[i], Batch = Positions, Next = i + 1 }))
                    return true;
            }

            return false;
        }

        internal static bool ContinueWindowPos(BinaryEmulator Instance, WinWindowPosChange Change, out ulong Result)
        {
            Result = 1;
            if (!Change.Changed)
            {
                WinWindow Window = Instance.WinHelper.GetWindow(Change.Position.Hwnd);
                if (Window == null || Window.Destroyed)
                {
                    if (Change.Batch == null)
                    {
                        Result = 0;
                        return false;
                    }
                }
                else
                {
                    Span<byte> Data = stackalloc byte[WindowPosStructSize];
                    if (Instance.ReadMemory(Change.WindowPos, Data, (uint)WindowPosStructSize))
                    {
                        ref Win32kDeferredWindowPos Position = ref Change.Position;
                        Position.InsertAfter = BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(0x08));
                        Position.X = BinaryPrimitives.ReadInt32LittleEndian(Data.Slice(0x10));
                        Position.Y = BinaryPrimitives.ReadInt32LittleEndian(Data.Slice(0x14));
                        Position.Width = BinaryPrimitives.ReadInt32LittleEndian(Data.Slice(0x18));
                        Position.Height = BinaryPrimitives.ReadInt32LittleEndian(Data.Slice(0x1C));
                        Position.Flags = BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(0x20));
                    }

                    if (FinishWindowPos(Instance, Window, Change))
                        return true;
                }
            }

            return Change.Batch != null && SendWindowPositions(Instance, Change.Batch, Change.Next);
        }

        // NT: xxxCalcValidRects and xxxSendChangedMsgs skip what did not change.
        private static bool FinishWindowPos(BinaryEmulator Instance, WinWindow Window, WinWindowPosChange Change)
        {
            int OldX = Window.X;
            int OldY = Window.Y;
            uint OldWidth = Window.Width;
            uint OldHeight = Window.Height;
            uint OldExStyle = Window.ExStyle;
            int OldZOrder = Instance.WinHelper.GetZOrderIndex(Window);
            GetClientRect(Instance, Window, out int OldClientX, out int OldClientY, out int OldClientWidth, out int OldClientHeight);

            ApplyWindowPos(Instance, Change.Position);
            Instance.WinHelper.PresentDesktop();

            uint Flags = Change.Position.Flags | SwpNoClientSize | SwpNoClientMove;
            if (Window.X == OldX && Window.Y == OldY)
                Flags |= SwpNoMove;
            if (Window.Width == OldWidth && Window.Height == OldHeight)
                Flags |= SwpNoSize;

            // NT: ValidateZorder drops a restack that changes nothing.
            if (Window.ExStyle == OldExStyle && Instance.WinHelper.GetZOrderIndex(Window) == OldZOrder)
                Flags |= SwpNoZOrder;

            GetClientRect(Instance, Window, out int ClientX, out int ClientY, out int ClientWidth, out int ClientHeight);
            if (ClientX != OldClientX || ClientY != OldClientY)
                Flags &= ~SwpNoClientMove;
            if (ClientWidth != OldClientWidth || ClientHeight != OldClientHeight)
                Flags &= ~SwpNoClientSize;

            if ((Flags & SwpChangeMask) == SwpNothingChanged)
                return false;

            if (!IsOwnedByCurrentThread(Instance, Window))
            {
                QueueWindowPosChanged(Instance, GetState(Instance), Window.Hwnd, Flags);
                return false;
            }

            Change.Position.X = Window.X;
            Change.Position.Y = Window.Y;
            Change.Position.Width = (int)Window.Width;
            Change.Position.Height = (int)Window.Height;
            Change.Position.Flags = Flags;
            Change.Changed = true;
            return SendWindowPosMessage(Instance, Window, WM_WINDOWPOSCHANGED, Change);
        }

        private static bool SendWindowPosMessage(BinaryEmulator Instance, WinWindow Window, uint Message, WinWindowPosChange Change)
        {
            if (!TryBeginWindowProcCallback(Instance, Window.WndProc, out ulong Callback, out ulong ArgumentBuffer))
                return false;

            Span<byte> Data = stackalloc byte[WindowPosStructSize];
            Data.Clear();
            WinSysHelper.WriteWindowPos(Data, true, Change.Position);

            ulong WindowPos = ArgumentBuffer + WindowProcArgumentHeaderSize;
            if (!Instance._emulator.WriteMemory(WindowPos, Data))
                return false;

            Change.WindowPos = WindowPos;
            WriteWindowProcCallbackArguments(Instance, ArgumentBuffer, Window.Hwnd, Window.WndProc, Message, 0, WindowPos);
            return Instance.WinHelper.EnterUserCallback(Callback, WindowProcCallbackIndex, ArgumentBuffer, null, PositionChange: Change);
        }

        private static bool IsOwnedByCurrentThread(BinaryEmulator Instance, WinWindow Window)
        {
            return Window.OwnerThreadId == (Instance.CurrentThread?.ThreadId ?? 0);
        }

        // NT: zzzBltValidBits. No bits are copied, so a moved child and a resized top-level window repaint whole.
        private static void InvalidateAfterWindowPos(BinaryEmulator Instance, WinWindow Window, bool WasVisible, uint Flags,
            int OldX, int OldY, uint OldWidth, uint OldHeight, bool Restacked)
        {
            const uint SWP_NOCOPYBITS = 0x0100;
            const uint CS_VREDRAW = 0x0001;
            const uint CS_HREDRAW = 0x0002;

            GdiClipRect Old = MakeRect(OldX, OldY, OldWidth, OldHeight);
            if (!Window.Visible)
            {
                if (!WasVisible)
                    return;

                ClearUpdateTree(Instance, Window);
                if ((Flags & SwpNoRedraw) == 0)
                    InvalidateParentArea(Instance, Window, Old);

                return;
            }

            bool Moved = Window.X != OldX || Window.Y != OldY;
            bool Sized = Window.Width != OldWidth || Window.Height != OldHeight;
            bool KeepsBits = WasVisible && (Flags & (SwpFrameChanged | SWP_NOCOPYBITS)) == 0;
            if ((Flags & SwpNoRedraw) != 0 || (KeepsBits && !Moved && !Sized && !Restacked))
                return;

            if (Window.ParentHwnd == 0)
            {
                if (!KeepsBits || Sized)
                    InvalidateWholeWindow(Instance, Window);

                return;
            }

            List<GdiClipRect> Invalid = GetState(Instance).RedrawArea;
            Invalid.Clear();
            if (WasVisible)
                UnionRect(Instance, Invalid, Old);

            UnionRect(Instance, Invalid, MakeRect(Window.X, Window.Y, Window.Width, Window.Height));

            uint ClassStyle = Instance.WinHelper.GetWindowClass(Window.ClassAtom)?.Style ?? 0;
            bool Redraws = (Window.Width != OldWidth && (ClassStyle & CS_HREDRAW) != 0)
                || (Window.Height != OldHeight && (ClassStyle & CS_VREDRAW) != 0);

            List<GdiClipRect> Valid = GetState(Instance).InvalidateSubtract;
            Valid.Clear();
            if (KeepsBits && !Restacked && !Redraws)
            {
                if (Moved)
                {
                    Valid.Add(MakeRect(Window.X, Window.Y, Window.Width, Window.Height));
                }
                else
                {
                    GetFrameInsets(Instance, Window, out int InsetLeft, out int InsetTop, out int InsetRight, out int InsetBottom);
                    GetClientRect(Instance, Window, out int ClientLeft, out int ClientTop, out int ClientWidth, out int ClientHeight);
                    long OldClientWidth = (long)OldWidth - InsetLeft - InsetRight;
                    long OldClientHeight = (long)OldHeight - InsetTop - InsetBottom;

                    GdiClipRect Both = MakeRect(ClientLeft, ClientTop, (uint)Math.Max(Math.Min(ClientWidth, OldClientWidth), 0),
                        (uint)Math.Max(Math.Min(ClientHeight, OldClientHeight), 0));
                    if (!IsEmpty(Both))
                        Valid.Add(Both);

                    if (Window.PaintPending)
                    {
                        foreach (GdiClipRect Owed in Window.UpdateRegion)
                            SubtractRect(Valid, ShiftRect(Owed, ClientLeft, ClientTop));
                    }
                }

                foreach (GdiClipRect Rect in Valid)
                    SubtractRect(Invalid, Rect);
            }

            if (Moved || Valid.Count == 0)
                InvalidateWholeWindow(Instance, Window);

            InvalidateParentArea(Instance, Window, Invalid);
        }

        // NT: invalidated in the parent with RDW_ERASE | RDW_ALLCHILDREN. The composed desktop keeps no update region.
        internal static void InvalidateParentArea(BinaryEmulator Instance, WinWindow Window)
        {
            InvalidateParentArea(Instance, Window, MakeRect(Window.X, Window.Y, Window.Width, Window.Height));
        }

        private static void InvalidateParentArea(BinaryEmulator Instance, WinWindow Window, in GdiClipRect Area)
        {
            List<GdiClipRect> Invalid = GetState(Instance).RedrawArea;
            Invalid.Clear();
            if (!IsEmpty(Area))
                Invalid.Add(Area);

            InvalidateParentArea(Instance, Window, Invalid);
        }

        private static void InvalidateParentArea(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Area)
        {
            WinWindow Parent = Window.ParentHwnd != 0 ? Instance.WinHelper.GetWindow(Window.ParentHwnd) : null;
            if (Parent == null || Parent.Destroyed || !Parent.Visible || Area.Count == 0)
                return;

            GetScreenRects(Instance, Parent, out _, out GdiClipRect ParentClient);
            List<GdiClipRect> Screen = GetState(Instance).InvalidateArea;
            Screen.Clear();
            foreach (GdiClipRect Rect in Area)
                Screen.Add(ShiftRect(Rect, ParentClient.Left, ParentClient.Top));

            InternalInvalidate(Instance, Parent, Screen, RdwUncovered);
            Instance.WinHelper.PresentInvalidation();
        }

        internal static ulong BeginDeferWindowPos(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            ulong Handle = State.NextDeferHandle++;
            State.DeferredWindowPositions[Handle] = new List<Win32kDeferredWindowPos>();
            return Handle;
        }

        internal static bool DeferWindowPos(BinaryEmulator Instance, ulong Handle, in Win32kDeferredWindowPos Position)
        {
            if (!GetState(Instance).DeferredWindowPositions.TryGetValue(Handle, out List<Win32kDeferredWindowPos> Positions))
                return false;

            Positions.Add(Position);
            return true;
        }

        // Pending while a window procedure runs. ContinueWindowPos then finishes the batch.
        internal static bool EndDeferWindowPos(BinaryEmulator Instance, ulong Handle, out bool Pending)
        {
            Pending = false;
            Win32kState State = GetState(Instance);
            if (!State.DeferredWindowPositions.Remove(Handle, out List<Win32kDeferredWindowPos> Positions))
                return false;

            Pending = SendWindowPositions(Instance, Positions, 0);
            return true;
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

        internal static ulong CreateDeviceContext(BinaryEmulator Instance, ulong Hwnd, bool WindowDc, bool PaintDc, bool Display = false)
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
                Display = Display || Hwnd != 0,
                SelectedBitmap = EnsureStockBitmap(Instance),
            };
            PublishDcVisibleArea(Instance, GdiHandle);
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
            PublishDcVisibleArea(Instance, Hdc);
            return true;
        }

        // gdi32 answers a batched SelectClipRgn from the visible bounds in DC_ATTR.
        internal static void PublishDcVisibleArea(BinaryEmulator Instance, ulong Hdc)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return;

            List<GdiClipRect> Area = GetState(Instance).DcArea;
            GetDcVisibleArea(Instance, Dc, Area);
            GetRegionBounds(Area, out GdiClipRect Bounds);
            Instance.WinHelper.WriteDcVisibleArea(Hdc, GetRegionType(Area), Bounds.Left, Bounds.Top, Bounds.Right, Bounds.Bottom);
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

        internal static ulong CreatePaletteHandle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.AllocateGdiHandle(PaletteHandleType);

            Instance.SetLastWinError(Handle == 0 ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS);
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

        // A blit block is built in host memory, so a guest extent gets the budget a bitmap gets.
        internal static bool IsBlitExtentValid(int Width, int Height)
        {
            return Width > 0 && Height > 0 && (long)Width * Height <= MaxBlitPixels;
        }

        // A stock object outlives every caller, so DeleteObject on one succeeds. Every window DC reports the
        // one display surface, which is shared the same way.
        internal static bool IsStockObject(BinaryEmulator Instance, ulong Handle)
        {
            if (Handle == 0)
                return false;

            Win32kState State = GetState(Instance);
            return Handle == State.StockBitmap || Handle == State.DisplaySurfaceBitmap;
        }

        // Every DC starts on this, so a caller that selects its own bitmap has one to select back.
        internal static ulong EnsureStockBitmap(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            if (State.StockBitmap == 0)
                State.StockBitmap = CreateBitmap(Instance, 1, 1, 1, 1, false, false);

            return State.StockBitmap;
        }

        internal static ulong CreateCompatibleBitmap(BinaryEmulator Instance, ulong Hdc, int Width, int Height)
        {
            if (!TryGetBitmap(Instance, GetDcSelectedBitmap(Instance, Hdc), out Win32kBitmap Source))
                return 0;

            // The caller deletes what it gets back, so a zero extent still needs its own bitmap.
            if (Width == 0 || Height == 0)
                return CreateBitmap(Instance, 1, 1, 1, 1, false, false);

            return CreateBitmap(Instance, Width, Height, Source.Planes, Source.BitsPerPixel, false, false);
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

        // Rows zero copies every row.
        internal static ulong CopyBitmap(BinaryEmulator Instance, ulong Handle, int Rows = 0)
        {
            if (!TryGetBitmap(Instance, Handle, out Win32kBitmap Source) || !Instance.IsRegionMapped(Source.BitsAddress, Source.BitsSize))
                return 0;

            int Height = Rows > 0 && Rows < Source.Height ? Rows : Source.Height;
            ulong Copy = CreateBitmap(Instance, Source.Width, Height, Source.Planes, Source.BitsPerPixel, false, Source.TopDown);
            if (Copy == 0 || !TryGetBitmap(Instance, Copy, out Win32kBitmap Target))
                return 0;

            int RowBytes = Math.Min(Source.Stride, Target.Stride);
            Span<byte> Row = Instance.WinHelper.Shared.GetSpan((ulong)RowBytes).Slice(0, RowBytes);
            for (int Y = 0; Y < Height; Y++)
            {
                int SourceLine = Source.TopDown ? Y : Source.Height - 1 - Y;
                int TargetLine = Target.TopDown ? Y : Height - 1 - Y;
                ulong From = Source.BitsAddress + (ulong)((long)SourceLine * Source.Stride);
                ulong To = Target.BitsAddress + (ulong)((long)TargetLine * Target.Stride);

                if (!Instance.ReadMemory(From, Row, (uint)RowBytes) || !Instance.WriteMemory(To, Row))
                {
                    RemoveBitmap(Instance, Copy);
                    Instance.WinHelper.FreeGdiHandle(Copy);
                    return 0;
                }
            }

            return Copy;
        }

        internal static bool TryRenderTextToDcBitmap(BinaryEmulator Instance, ulong Hdc, string Text, int X, int Y, uint Options)
        {
            Win32kState State = GetState(Instance);
            if (!State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc) || Dc.Hwnd != 0 || Dc.SelectedBitmap == 0)
                return false;

            if (!State.Bitmaps.TryGetValue(Dc.SelectedBitmap, out Win32kBitmap Bitmap)
                || !Bitmap.DibSection || Bitmap.BitsPerPixel != 32 || Bitmap.BitsAddress == 0
                || Bitmap.Width <= 0 || Bitmap.Height <= 0)
                return false;

            if (!Instance.IsRegionMapped(Bitmap.BitsAddress, Bitmap.BitsSize))
                return false;

            Instance.WinHelper.ReadDcTextColors(Hdc, out uint TextColor, out uint BackColor, out bool Opaque);
            if ((Options & EtoOpaque) != 0)
                Opaque = true;

            Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
            X += OffsetX;
            Y += OffsetY;
            TryGetDcClip(Instance, Hdc, out GdiClipRect[] Clip);

            int Count = Bitmap.Width * Bitmap.Height;
            uint[] Rented = ArrayPool<uint>.Shared.Rent(Count);
            try
            {
                Span<uint> Pixels = Rented.AsSpan(0, Count);
                if (!TransferBitmapRows(Instance, Bitmap, Pixels, false))
                    return false;

                if (!Instance.WinHelper.RasterizeText(ResolveDcFont(Instance, Hdc), Text, Pixels,
                        Bitmap.Width, Bitmap.Height, X, Y, TextColor, BackColor, Opaque))
                    return false;

                if (Clip == null)
                    return TransferBitmapRows(Instance, Bitmap, Pixels, true);

                foreach (GdiClipRect Rect in Clip)
                {
                    int Left = Math.Max(Rect.Left, 0);
                    int Right = Math.Min(Rect.Right, Bitmap.Width);
                    for (int Row = Math.Max(Rect.Top, 0); Row < Math.Min(Rect.Bottom, Bitmap.Height) && Left < Right; Row++)
                    {
                        if (!TryWriteBitmapRow(Instance, Bitmap, Row, Left, Right - Left, Pixels.Slice(Row * Bitmap.Width + Left, Right - Left)))
                            return false;
                    }
                }

                return true;
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Rented);
            }
        }

        // The buffer is top-down. A bottom-up DIB stores its first row last.
        private static bool TransferBitmapRows(BinaryEmulator Instance, in Win32kBitmap Bitmap, Span<uint> Pixels, bool ToGuest)
        {
            for (int Row = 0; Row < Bitmap.Height; Row++)
            {
                int GuestRow = Bitmap.TopDown ? Row : Bitmap.Height - 1 - Row;
                ulong Address = Bitmap.BitsAddress + (ulong)((long)GuestRow * Bitmap.Stride);
                Span<byte> Line = MemoryMarshal.AsBytes(Pixels.Slice(Row * Bitmap.Width, Bitmap.Width));

                if (ToGuest)
                {
                    if (!Instance.WriteMemory(Address, Line))
                        return false;
                }
                else if (!Instance.ReadMemory(Address, Line, (uint)Line.Length))
                {
                    return false;
                }
            }

            return true;
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

        internal const int BitmapCoreHeaderSize = 12;
        internal const int BitmapInfoHeaderSize = 40;
        internal const uint BI_RGB = 0;
        internal const uint BI_BITFIELDS = 3;

        internal struct DibHeader
        {
            public int Width;
            public int Height;
            public ushort Planes;
            public ushort BitsPerPixel;
            public uint Compression;
            public uint HeaderSize;
            public bool TopDown => Height < 0;
            public int Rows => Height < 0 ? -Height : Height;
        }

        internal static bool TryReadDibHeader(BinaryEmulator Instance, ulong Address, out DibHeader Header)
        {
            Header = default;

            if (Address == 0 || !Instance.IsRegionMapped(Address, BitmapCoreHeaderSize))
                return false;

            uint HeaderSize = Instance.ReadMemoryUInt(Address);
            int ReadSize = HeaderSize == BitmapCoreHeaderSize ? BitmapCoreHeaderSize : BitmapInfoHeaderSize;
            if (HeaderSize != BitmapCoreHeaderSize && HeaderSize < BitmapInfoHeaderSize)
                return false;

            if (!Instance.IsRegionMapped(Address, (ulong)ReadSize))
                return false;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)ReadSize);
            if (!Instance.ReadMemory(Address, Buffer, (uint)ReadSize))
                return false;

            Header.HeaderSize = HeaderSize;

            if (ReadSize == BitmapCoreHeaderSize)
            {
                Header.Width = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0x04, 2));
                Header.Height = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0x06, 2));
                Header.Planes = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0x08, 2));
                Header.BitsPerPixel = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0x0A, 2));
                Header.Compression = BI_RGB;
                return true;
            }

            Header.Width = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x04, 4));
            Header.Height = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x08, 4));
            Header.Planes = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0x0C, 2));
            Header.BitsPerPixel = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0x0E, 2));
            Header.Compression = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x10, 4));
            return true;
        }

        internal static bool TryReadDibBlock(BinaryEmulator Instance, ulong BitsAddress, in DibHeader Header,
            int X, int Y, int Width, int Height, Span<uint> Destination)
        {
            if (BitsAddress == 0 || Header.Planes != 1 || Width <= 0 || Height <= 0)
                return false;

            if (Header.Compression != BI_RGB && Header.Compression != BI_BITFIELDS)
                return false;

            if (Header.BitsPerPixel != 32 && Header.BitsPerPixel != 24)
                return false;

            int Rows = Header.Rows;
            int BytesPerPixel = Header.BitsPerPixel / 8;
            int Stride = GetBitmapStride(Header.Width, 1, Header.BitsPerPixel, true);
            if (Header.Width <= 0 || Rows <= 0 || Stride <= 0)
                return false;

            if (!Instance.IsRegionMapped(BitsAddress, (ulong)((long)Stride * Rows)))
                return false;

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Stride);
            try
            {
                Span<byte> Line = Rented.AsSpan(0, Stride);

                for (int Row = 0; Row < Height; Row++)
                {
                    Span<uint> Target = Destination.Slice(Row * Width, Width);
                    int SourceRow = Y + Row;
                    if ((uint)SourceRow >= (uint)Rows)
                    {
                        Target.Clear();
                        continue;
                    }

                    int StoredRow = Header.TopDown ? SourceRow : Rows - 1 - SourceRow;
                    if (!Instance.ReadMemory(BitsAddress + (ulong)((long)StoredRow * Stride), Line, (uint)Stride))
                        return false;

                    for (int Column = 0; Column < Width; Column++)
                    {
                        int SourceColumn = X + Column;
                        if ((uint)SourceColumn >= (uint)Header.Width)
                        {
                            Target[Column] = 0;
                            continue;
                        }

                        int Offset = SourceColumn * BytesPerPixel;
                        Target[Column] = (uint)(Line[Offset] | (Line[Offset + 1] << 8) | (Line[Offset + 2] << 16));
                    }
                }

                return true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        // Layout of the region object NtGdiCreateRectRgn builds.
        internal const int RegionObjectSize = 0x30;
        private const int RegionTypeOffset = 0x04;

        internal const int RegionNull = 1;
        internal const int RegionSimple = 2;
        internal const int RegionComplex = 3;
        internal const int RegionError = 0;

        // A complex region keeps its rectangles here. gdi32 reads a simple one from the attribute block.
        internal static bool TryReadRegion(BinaryEmulator Instance, ulong Handle, List<GdiClipRect> Rects)
        {
            Rects.Clear();

            ulong Object = Instance.WinHelper.GetGdiKernelObject(Handle, RegionHandleType);
            if (Object == 0 || !Instance.IsRegionMapped(Object, RegionObjectSize))
                return false;

            Span<byte> Buffer = stackalloc byte[20];
            if (!Instance.ReadMemory(Object + RegionTypeOffset, Buffer))
                return false;

            int Type = BinaryPrimitives.ReadInt32LittleEndian(Buffer);
            if (Type == RegionComplex && GetState(Instance).RegionRects.TryGetValue(Handle, out GdiClipRect[] Stored))
            {
                Rects.AddRange(Stored);
                return true;
            }

            GdiClipRect Rect = new GdiClipRect
            {
                Left = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(4)),
                Top = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(8)),
                Right = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(12)),
                Bottom = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(16)),
            };

            if (Rect.Left < Rect.Right && Rect.Top < Rect.Bottom)
                Rects.Add(Rect);

            return true;
        }

        internal static int WriteRegion(BinaryEmulator Instance, ulong Handle, List<GdiClipRect> Rects)
        {
            ulong Object = Instance.WinHelper.GetGdiKernelObject(Handle, RegionHandleType);
            if (Object == 0 || !Instance.IsRegionMapped(Object, RegionObjectSize))
                return RegionError;

            int Type = GetRegionType(Rects);
            GetRegionBounds(Rects, out GdiClipRect Bounds);

            Span<byte> Buffer = stackalloc byte[20];
            BinaryPrimitives.WriteInt32LittleEndian(Buffer, Type);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4), Bounds.Left);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(8), Bounds.Top);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(12), Bounds.Right);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(16), Bounds.Bottom);
            if (!Instance.WriteMemory(Object + RegionTypeOffset, Buffer))
                return RegionError;

            Dictionary<ulong, GdiClipRect[]> Stored = GetState(Instance).RegionRects;
            if (Type == RegionComplex)
                Stored[Handle] = Rects.ToArray();
            else
                Stored.Remove(Handle);

            return Type;
        }

        internal static int GetRegionType(List<GdiClipRect> Rects) => GetRegionType(Rects.Count);

        private static int GetRegionType(int RectCount)
        {
            return RectCount == 0 ? RegionNull : RectCount == 1 ? RegionSimple : RegionComplex;
        }

        internal static void GetRegionBounds(List<GdiClipRect> Rects, out GdiClipRect Bounds)
        {
            Bounds = default;
            if (Rects.Count == 0)
                return;

            Bounds = Rects[0];
            for (int i = 1; i < Rects.Count; i++)
            {
                Bounds.Left = Math.Min(Bounds.Left, Rects[i].Left);
                Bounds.Top = Math.Min(Bounds.Top, Rects[i].Top);
                Bounds.Right = Math.Max(Bounds.Right, Rects[i].Right);
                Bounds.Bottom = Math.Max(Bounds.Bottom, Rects[i].Bottom);
            }
        }

        internal const int RgnAnd = 1;
        internal const int RgnOr = 2;
        internal const int RgnXor = 3;
        internal const int RgnDiff = 4;
        internal const int RgnCopy = 5;

        internal static bool CombineRegions(List<GdiClipRect> A, List<GdiClipRect> B, int Mode, List<GdiClipRect> Result)
        {
            return CombineRegions(CollectionsMarshal.AsSpan(A), CollectionsMarshal.AsSpan(B), Mode, Result);
        }

        // Inputs and result are disjoint rectangles. Result must not share storage with an input.
        internal static bool CombineRegions(ReadOnlySpan<GdiClipRect> A, ReadOnlySpan<GdiClipRect> B, int Mode, List<GdiClipRect> Result)
        {
            Result.Clear();
            switch (Mode)
            {
                case RgnCopy:
                    Result.AddRange(A);
                    return true;

                case RgnAnd:
                    foreach (GdiClipRect First in A)
                    {
                        foreach (GdiClipRect Second in B)
                        {
                            GdiClipRect Rect = Intersect(First, Second);
                            if (!IsEmpty(Rect))
                                Result.Add(Rect);
                        }
                    }
                    return true;

                case RgnDiff:
                    Result.AddRange(A);
                    foreach (GdiClipRect Cut in B)
                        SubtractRect(Result, Cut);
                    return true;

                case RgnOr:
                    Result.AddRange(B);
                    foreach (GdiClipRect Cut in A)
                        SubtractRect(Result, Cut);
                    Result.AddRange(A);
                    return true;

                case RgnXor:
                    List<GdiClipRect> Other = XorScratch ??= new List<GdiClipRect>();
                    Other.Clear();
                    Other.AddRange(B);
                    foreach (GdiClipRect Cut in A)
                        SubtractRect(Other, Cut);
                    Result.AddRange(A);
                    foreach (GdiClipRect Cut in B)
                        SubtractRect(Result, Cut);
                    Result.AddRange(Other);
                    return true;
            }

            return false;
        }

        [ThreadStatic]
        private static List<GdiClipRect> XorScratch;

        private static void GetDcDeviceExtent(BinaryEmulator Instance, Win32kDeviceContext Dc, out GdiClipRect Extent)
        {
            Extent = default;

            if (Dc.Hwnd != 0)
            {
                GetClientSize(Instance, Instance.WinHelper.GetWindow(Dc.Hwnd), out Extent.Right, out Extent.Bottom);
                return;
            }

            if (Dc.Display)
            {
                Extent.Right = HostDisplayMetrics.ScreenWidth;
                Extent.Bottom = HostDisplayMetrics.ScreenHeight;
                return;
            }

            if (GetState(Instance).Bitmaps.TryGetValue(Dc.SelectedBitmap, out Win32kBitmap Bitmap))
            {
                Extent.Right = Bitmap.Width;
                Extent.Bottom = Bitmap.Height;
            }
        }

        private static void GetDcVisibleArea(BinaryEmulator Instance, Win32kDeviceContext Dc, List<GdiClipRect> Rects)
        {
            Rects.Clear();
            GetDcDeviceExtent(Instance, Dc, out GdiClipRect Extent);
            if (Extent.Right <= Extent.Left || Extent.Bottom <= Extent.Top)
                return;

            AddClientVisibleArea(Instance, Dc.Hwnd, Dc.Hwnd != 0 ? Instance.WinHelper.GetWindowClip(Dc.Hwnd) : null, Extent, Rects);

            if (Dc.PaintArea != null)
                IntersectRegion(Instance, Rects, Dc.PaintArea);
        }

        // Rects must not be DcWork.
        private static void IntersectRegion(BinaryEmulator Instance, List<GdiClipRect> Rects, ReadOnlySpan<GdiClipRect> Other)
        {
            List<GdiClipRect> Work = GetState(Instance).DcWork;
            Work.Clear();
            Work.AddRange(Rects);
            CombineRegions(CollectionsMarshal.AsSpan(Work), Other, RgnAnd, Rects);
        }

        private static void AddClientVisibleArea(BinaryEmulator Instance, ulong Hwnd, GdiClipRect[] Visible, in GdiClipRect Extent, List<GdiClipRect> Rects)
        {
            if (Visible == null)
            {
                Rects.Add(Extent);
                return;
            }

            AddSurfaceRectsAsClient(Instance, Hwnd, Visible, Rects);
            WinSysHelper.IntersectClip(Rects, Extent);
        }

        private static void AddSurfaceRectsAsClient(BinaryEmulator Instance, ulong Hwnd, GdiClipRect[] Surface, List<GdiClipRect> Client)
        {
            Instance.WinHelper.GetSurfaceOrigin(Hwnd, out int SurfaceX, out int SurfaceY);
            foreach (GdiClipRect Rect in Surface)
                Client.Add(ShiftRect(Rect, -(long)SurfaceX, -(long)SurfaceY));
        }

        private static void GetDcEffectiveArea(BinaryEmulator Instance, Win32kDeviceContext Dc, List<GdiClipRect> Rects)
        {
            GetDcVisibleArea(Instance, Dc, Rects);
            if (Dc.Clip == null)
                return;

            IntersectRegion(Instance, Rects, Dc.Clip);
        }

        // NT: with no clip region, a combination starts from the whole surface of the DC.
        private static List<GdiClipRect> GetDcClipBase(BinaryEmulator Instance, Win32kDeviceContext Dc, List<GdiClipRect> Base)
        {
            Base.Clear();
            if (Dc.Clip != null)
            {
                Base.AddRange(Dc.Clip);
                return Base;
            }

            GetDcDeviceExtent(Instance, Dc, out GdiClipRect Extent);
            if (Extent.Right > Extent.Left && Extent.Bottom > Extent.Top)
                Base.Add(Extent);
            return Base;
        }

        // NT reports COMPLEXREGION for any clip that is not empty.
        internal static int ClipDcRect(BinaryEmulator Instance, ulong Hdc, int Left, int Top, int Right, int Bottom, bool Exclude)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return RegionError;

            Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
            GdiClipRect Rect = new GdiClipRect
            {
                Left = Math.Min(Left, Right) + OffsetX,
                Top = Math.Min(Top, Bottom) + OffsetY,
                Right = Math.Max(Left, Right) + OffsetX,
                Bottom = Math.Max(Top, Bottom) + OffsetY,
            };

            List<GdiClipRect> Clip = GetState(Instance).RegionA;
            if (Exclude)
            {
                GetDcClipBase(Instance, Dc, Clip);
                SubtractRect(Clip, Rect);
            }
            else if (Dc.Clip == null)
            {
                Clip.Clear();
                if (Rect.Left < Rect.Right && Rect.Top < Rect.Bottom)
                    Clip.Add(Rect);
            }
            else
            {
                Clip.Clear();
                Clip.AddRange(Dc.Clip);
                WinSysHelper.IntersectClip(Clip, Rect);
            }

            Dc.Clip = Clip.ToArray();
            return Clip.Count == 0 ? RegionNull : RegionComplex;
        }

        internal static int SelectDcClipRegion(BinaryEmulator Instance, ulong Hdc, ulong Region, int Mode)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return RegionError;

            if (Region == 0)
            {
                if (Mode != RgnCopy)
                    return RegionError;

                Dc.Clip = null;
                return RegionSimple;
            }

            List<GdiClipRect> Source = GetState(Instance).RegionA;
            if (!TryReadRegion(Instance, Region, Source))
                return RegionError;

            return SetDcClip(Instance, Dc, Source, Mode);
        }

        // The reset flag with RGN_COPY drops the clip region.
        internal static int SelectDcClipRect(BinaryEmulator Instance, ulong Hdc, int Mode, GdiClipRect Rect)
        {
            const int ResetFlag = 0x08000000;

            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return RegionError;

            if ((Mode & ResetFlag) != 0)
            {
                Dc.Clip = null;
                return RegionSimple;
            }

            List<GdiClipRect> Source = GetState(Instance).RegionA;
            Source.Clear();
            if (Rect.Left < Rect.Right && Rect.Top < Rect.Bottom)
                Source.Add(Rect);

            return SetDcClip(Instance, Dc, Source, Mode);
        }

        // Source must not be RegionB or RegionResult.
        private static int SetDcClip(BinaryEmulator Instance, Win32kDeviceContext Dc, List<GdiClipRect> Source, int Mode)
        {
            Win32kState State = GetState(Instance);
            List<GdiClipRect> Result = State.RegionResult;
            Result.Clear();
            if (Mode == RgnCopy)
                Result.AddRange(Source);
            else if (!CombineRegions(GetDcClipBase(Instance, Dc, State.RegionB), Source, Mode, Result))
                return RegionError;

            Dc.Clip = Result.ToArray();
            return GetRegionType(Result);
        }

        internal static bool DeleteGdiObject(BinaryEmulator Instance, ulong Handle)
        {
            if (IsStockObject(Instance, Handle))
                return true;

            RemovePenBrush(Instance, Handle);
            RemoveBitmap(Instance, Handle);
            RemoveFont(Instance, Handle);
            GetState(Instance).RegionRects.Remove(Handle);
            return Instance.WinHelper.FreeGdiHandle(Handle);
        }

        internal static int OffsetDcClip(BinaryEmulator Instance, ulong Hdc, int X, int Y)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return RegionError;

            if (Dc.Clip == null)
                return RegionSimple;

            GdiClipRect[] Moved = new GdiClipRect[Dc.Clip.Length];
            for (int i = 0; i < Moved.Length; i++)
                Moved[i] = ShiftRect(Dc.Clip[i], X, Y);

            Dc.Clip = Moved;
            return GetRegionType(Moved.Length);
        }

        // In logical coordinates.
        internal static int GetDcClipBox(BinaryEmulator Instance, ulong Hdc, out GdiClipRect Box)
        {
            Box = default;
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return RegionError;

            List<GdiClipRect> Area = GetState(Instance).DcArea;
            GetDcEffectiveArea(Instance, Dc, Area);
            GetRegionBounds(Area, out Box);

            if (Area.Count != 0)
            {
                Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
                Box.Left -= OffsetX;
                Box.Right -= OffsetX;
                Box.Top -= OffsetY;
                Box.Bottom -= OffsetY;
            }

            return GetRegionType(Area);
        }

        private const int RandomRegionClip = 1;
        private const int RandomRegionMeta = 2;
        private const int RandomRegionApi = 3;
        private const int RandomRegionSystem = 4;

        // CLIPRGN is in device coordinates, SYSRGN in screen coordinates.
        internal static int GetDcRandomRegion(BinaryEmulator Instance, ulong Hdc, ulong Region, int Code)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return -1;

            List<GdiClipRect> Rects = GetState(Instance).DcArea;
            Rects.Clear();
            switch (Code)
            {
                case RandomRegionClip:
                case RandomRegionApi:
                    if (Dc.Clip == null)
                        return 0;
                    Rects.AddRange(Dc.Clip);
                    break;

                case RandomRegionMeta:
                    return 0;

                case RandomRegionSystem:
                    GetDcVisibleArea(Instance, Dc, Rects);
                    if (Dc.Hwnd != 0)
                    {
                        GetClientScreenOrigin(Instance, Dc.Hwnd, out int ScreenX, out int ScreenY);
                        for (int i = 0; i < Rects.Count; i++)
                            Rects[i] = ShiftRect(Rects[i], ScreenX, ScreenY);
                    }
                    break;

                default:
                    return -1;
            }

            return WriteRegion(Instance, Region, Rects) == RegionError ? -1 : 1;
        }

        internal static bool IsDcAreaVisible(BinaryEmulator Instance, ulong Hdc, int Left, int Top, int Right, int Bottom)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return false;

            Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
            Left += OffsetX;
            Right += OffsetX;
            Top += OffsetY;
            Bottom += OffsetY;

            List<GdiClipRect> Area = GetState(Instance).DcArea;
            GetDcEffectiveArea(Instance, Dc, Area);
            foreach (GdiClipRect Rect in Area)
            {
                if (Left < Rect.Right && Right > Rect.Left && Top < Rect.Bottom && Bottom > Rect.Top)
                    return true;
            }

            return false;
        }

        internal static void SetDcPaintArea(BinaryEmulator Instance, ulong Hdc, List<GdiClipRect> Area)
        {
            if (GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                Dc.PaintArea = Area.ToArray();
        }

        // Device coordinates.
        internal static bool TryGetDcClip(BinaryEmulator Instance, ulong Hdc, out GdiClipRect[] Clip)
        {
            Clip = null;
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc) || (Dc.Clip == null && Dc.PaintArea == null))
                return false;

            if (Dc.PaintArea == null || Dc.Clip == null)
            {
                Clip = Dc.Clip ?? Dc.PaintArea;
                return true;
            }

            if (Dc.CombinedClip == null || !ReferenceEquals(Dc.CombinedClipSource, Dc.Clip) || !ReferenceEquals(Dc.CombinedPaintArea, Dc.PaintArea))
            {
                List<GdiClipRect> Rects = new List<GdiClipRect>();
                CombineRegions(Dc.Clip, Dc.PaintArea, RgnAnd, Rects);
                Dc.CombinedClip = Rects.ToArray();
                Dc.CombinedClipSource = Dc.Clip;
                Dc.CombinedPaintArea = Dc.PaintArea;
            }

            Clip = Dc.CombinedClip;
            return true;
        }

        // Surface coordinates.
        internal static GdiClipRect[] GetDcDrawClip(BinaryEmulator Instance, ulong Hdc, GdiClipRect[] Visible, int SurfaceX, int SurfaceY)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc) || !TryGetDcClip(Instance, Hdc, out GdiClipRect[] DcClip))
                return Visible;

            if (Dc.DrawClip != null && ReferenceEquals(Dc.DrawClipSource, DcClip) && ReferenceEquals(Dc.DrawClipVisible, Visible)
                && Dc.DrawClipX == SurfaceX && Dc.DrawClipY == SurfaceY)
            {
                return Dc.DrawClip;
            }

            List<GdiClipRect> Rects = new List<GdiClipRect>(DcClip.Length);
            foreach (GdiClipRect Rect in DcClip)
                Rects.Add(ShiftRect(Rect, SurfaceX, SurfaceY));

            GdiClipRect[] Result;
            if (Visible == null)
            {
                Result = Rects.ToArray();
            }
            else
            {
                List<GdiClipRect> Combined = new List<GdiClipRect>();
                CombineRegions(CollectionsMarshal.AsSpan(Rects), Visible, RgnAnd, Combined);
                Result = Combined.ToArray();
            }

            Dc.DrawClip = Result;
            Dc.DrawClipSource = DcClip;
            Dc.DrawClipVisible = Visible;
            Dc.DrawClipX = SurfaceX;
            Dc.DrawClipY = SurfaceY;
            return Result;
        }

        internal static bool PatBltDc(BinaryEmulator Instance, ulong Hdc, int X, int Y, int Width, int Height, uint Rop, ulong Brush)
        {
            Win32kPenBrush Resolved = ResolvePenBrush(Instance, Brush, false);
            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd != 0)
            {
                Instance.WinHelper.EnqueueGdiFillRect(Hwnd, Hdc, X, Y, X + Width, Y + Height, Resolved.ColorRef, Rop);
                return true;
            }

            if (!TryGetDcBitmap(Instance, Hdc, out Win32kBitmap Target) || !CanBlitBitmap(Target))
                return false;

            if (Width < 0)
            {
                X += Width;
                Width = -Width;
            }

            if (Height < 0)
            {
                Y += Height;
                Height = -Height;
            }

            if (Width == 0 || Height == 0)
                return true;

            Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
            TryGetDcClip(Instance, Hdc, out GdiClipRect[] Clip);
            uint PatternPixel = HostColor.FromColorRef(Resolved.ColorRef);
            ReadOnlySpan<uint> Unused = stackalloc uint[1];
            return TryBlitBlockIntoBitmap(Instance, Target, X + OffsetX, Y + OffsetY, Width, Height, Unused, 1, 1, Rop, PatternPixel, Clip);
        }

        internal const uint SrcCopyRop = 0x00CC0020;

        internal static ulong FindDcForBitmap(BinaryEmulator Instance, ulong BitmapHandle)
        {
            if (BitmapHandle == 0)
                return 0;

            foreach (KeyValuePair<ulong, Win32kDeviceContext> Entry in GetState(Instance).DeviceContexts)
            {
                if (Entry.Value.SelectedBitmap == BitmapHandle)
                    return Entry.Key;
            }

            return 0;
        }

        internal static int SaveDeviceContext(BinaryEmulator Instance, ulong Hdc)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return 0;

            byte[] Attributes = null;
            ulong AttributeBlock = Instance.WinHelper.GetDcAttributeAddress(Hdc);
            if (AttributeBlock != 0)
            {
                Attributes = new byte[DcAttributeSaveSize];
                if (!Instance.ReadMemory(AttributeBlock, Attributes))
                    Attributes = null;
            }

            Dc.SavedStates ??= new List<Win32kDcState>();
            Dc.SavedStates.Add(new Win32kDcState { Bitmap = Dc.SelectedBitmap, Font = Dc.SelectedFont, Clip = Dc.Clip, Attributes = Attributes });
            return Dc.SavedStates.Count;
        }

        internal static bool RestoreDeviceContext(BinaryEmulator Instance, ulong Hdc, int Level)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc)
                || Dc.SavedStates == null || Dc.SavedStates.Count == 0)
                return false;

            // A negative level counts back from the top, so RestoreDC(-1) pops one state.
            int Target = Level < 0 ? Dc.SavedStates.Count + Level : Level - 1;
            if ((uint)Target >= (uint)Dc.SavedStates.Count)
                return false;

            Win32kDcState Saved = Dc.SavedStates[Target];
            Dc.SelectedBitmap = Saved.Bitmap;
            Dc.SelectedFont = Saved.Font;
            Dc.Clip = Saved.Clip;
            Dc.SavedStates.RemoveRange(Target, Dc.SavedStates.Count - Target);

            ulong AttributeBlock = Instance.WinHelper.GetDcAttributeAddress(Hdc);
            if (Saved.Attributes != null && AttributeBlock != 0)
                Instance.WriteMemory(AttributeBlock, Saved.Attributes);

            PublishDcVisibleArea(Instance, Hdc);
            return true;
        }

        internal static ulong SelectDcPalette(BinaryEmulator Instance, ulong Hdc, ulong Palette)
        {
            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return 0;

            ulong Previous = Dc.SelectedPalette;
            Dc.SelectedPalette = Palette;
            return Previous;
        }

        // A screen context reports the display surface, not the bitmap selected into it.
        internal static ulong GetDcSelectedBitmap(BinaryEmulator Instance, ulong Hdc)
        {
            Win32kState State = GetState(Instance);
            if (!State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return 0;

            return Dc.Display ? EnsureDisplaySurfaceBitmap(Instance, State) : Dc.SelectedBitmap;
        }

        private static ulong EnsureDisplaySurfaceBitmap(BinaryEmulator Instance, Win32kState State)
        {
            if (State.DisplaySurfaceBitmap == 0)
                State.DisplaySurfaceBitmap = CreateBitmap(Instance, HostDisplayMetrics.ScreenWidth, HostDisplayMetrics.ScreenHeight, 1, 32, false, false);

            return State.DisplaySurfaceBitmap;
        }

        internal static ulong GetDcSelectedFont(BinaryEmulator Instance, ulong Hdc)
        {
            return GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc) ? Dc.SelectedFont : 0;
        }

        // gdi32 asks twice, once for the size and once for the data.
        internal static IReadOnlyList<FontFamilyData> GetFontFamilies(BinaryEmulator Instance, string FaceName, byte CharSet)
        {
            Win32kState State = GetState(Instance);
            string Key = CharSet.ToString(CultureInfo.InvariantCulture) + "|" + (FaceName ?? string.Empty);

            if (State.FontFamilies.TryGetValue(Key, out IReadOnlyList<FontFamilyData> Cached))
                return Cached;

            IReadOnlyList<FontFamilyData> Faces = Instance.WinHelper.EnumerateFontFamilies(FaceName, CharSet) ?? Array.Empty<FontFamilyData>();
            State.FontFamilies[Key] = Faces;
            return Faces;
        }

        internal static ulong GetDcSelectedPalette(BinaryEmulator Instance, ulong Hdc)
        {
            return GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc) ? Dc.SelectedPalette : 0;
        }

        internal static bool TryGetDcExtent(BinaryEmulator Instance, ulong Hdc, out int Width, out int Height)
        {
            Width = 0;
            Height = 0;

            if (!GetState(Instance).DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return false;

            if (Dc.Hwnd != 0)
            {
                GetClientSize(Instance, Instance.WinHelper.GetWindow(Dc.Hwnd), out Width, out Height);
                return true;
            }

            if (!TryGetDcBitmap(Instance, Hdc, out Win32kBitmap Bitmap))
                return false;

            Width = Bitmap.Width;
            Height = Bitmap.Height;
            return true;
        }

        // A window DC draws through the host window, so only a screen context resolves to the display surface.
        internal static bool TryGetDcBitmap(BinaryEmulator Instance, ulong Hdc, out Win32kBitmap Bitmap)
        {
            Win32kState State = GetState(Instance);
            Bitmap = default;

            if (!State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return false;

            ulong Handle = Dc.Display && Dc.Hwnd == 0 ? EnsureDisplaySurfaceBitmap(Instance, State) : Dc.SelectedBitmap;
            return Handle != 0 && State.Bitmaps.TryGetValue(Handle, out Bitmap);
        }

        // Packed colour only. Lower depths need a colour table the blit does not carry.
        internal static bool CanBlitBitmap(in Win32kBitmap Bitmap)
        {
            return Bitmap.Planes == 1
                && (Bitmap.BitsPerPixel == 32 || Bitmap.BitsPerPixel == 24)
                && Bitmap.BitsAddress != 0
                && Bitmap.Width > 0
                && Bitmap.Height > 0;
        }

        // Flipping the term changes the result for at least one of the other four combinations.
        internal static bool RopUsesSource(uint Rop)
        {
            uint Index = (Rop >> 16) & 0xFF;
            return ((Index >> 2) & 0x33) != (Index & 0x33);
        }

        internal static bool RopUsesDestination(uint Rop)
        {
            uint Index = (Rop >> 16) & 0xFF;
            return ((Index >> 1) & 0x55) != (Index & 0x55);
        }

        // Index is bits 16 to 23 of the rop code.
        internal static uint ApplyRop(uint Index, uint Pattern, uint Source, uint Destination)
        {
            uint Result = 0;

            if ((Index & 0x01) != 0) Result |= ~Pattern & ~Source & ~Destination;
            if ((Index & 0x02) != 0) Result |= ~Pattern & ~Source & Destination;
            if ((Index & 0x04) != 0) Result |= ~Pattern & Source & ~Destination;
            if ((Index & 0x08) != 0) Result |= ~Pattern & Source & Destination;
            if ((Index & 0x10) != 0) Result |= Pattern & ~Source & ~Destination;
            if ((Index & 0x20) != 0) Result |= Pattern & ~Source & Destination;
            if ((Index & 0x40) != 0) Result |= Pattern & Source & ~Destination;
            if ((Index & 0x80) != 0) Result |= Pattern & Source & Destination;

            return Result & 0x00FFFFFF;
        }

        private static ulong BitmapRowAddress(in Win32kBitmap Bitmap, int Row)
        {
            int Line = Bitmap.TopDown ? Row : Bitmap.Height - 1 - Row;
            return Bitmap.BitsAddress + (ulong)((long)Line * Bitmap.Stride);
        }

        private static bool TryReadBitmapRow(BinaryEmulator Instance, in Win32kBitmap Bitmap, int Row, int X, int Width, Span<uint> Destination)
        {
            int BytesPerPixel = Bitmap.BitsPerPixel / 8;
            int Bytes = Width * BytesPerPixel;
            ulong Address = BitmapRowAddress(Bitmap, Row) + (ulong)(X * BytesPerPixel);

            if (BytesPerPixel == 4)
            {
                Span<byte> Line = MemoryMarshal.AsBytes(Destination.Slice(0, Width));
                return Instance.ReadMemory(Address, Line, (uint)Bytes);
            }

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Bytes);
            try
            {
                Span<byte> Line = Rented.AsSpan(0, Bytes);
                if (!Instance.ReadMemory(Address, Line, (uint)Bytes))
                    return false;

                for (int Column = 0; Column < Width; Column++)
                {
                    int Offset = Column * 3;
                    Destination[Column] = (uint)(Line[Offset] | (Line[Offset + 1] << 8) | (Line[Offset + 2] << 16));
                }

                return true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        private static bool TryWriteBitmapRow(BinaryEmulator Instance, in Win32kBitmap Bitmap, int Row, int X, int Width, ReadOnlySpan<uint> Source)
        {
            int BytesPerPixel = Bitmap.BitsPerPixel / 8;
            int Bytes = Width * BytesPerPixel;
            ulong Address = BitmapRowAddress(Bitmap, Row) + (ulong)(X * BytesPerPixel);

            if (BytesPerPixel == 4)
                return Instance.WriteMemory(Address, MemoryMarshal.AsBytes(Source.Slice(0, Width)));

            byte[] Rented = ArrayPool<byte>.Shared.Rent(Bytes);
            try
            {
                Span<byte> Line = Rented.AsSpan(0, Bytes);
                for (int Column = 0; Column < Width; Column++)
                {
                    uint Pixel = Source[Column];
                    int Offset = Column * 3;
                    Line[Offset] = (byte)Pixel;
                    Line[Offset + 1] = (byte)(Pixel >> 8);
                    Line[Offset + 2] = (byte)(Pixel >> 16);
                }

                return Instance.WriteMemory(Address, Line);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Rented);
            }
        }

        internal static bool TryReadBitmapBlock(BinaryEmulator Instance, in Win32kBitmap Bitmap, int X, int Y, int Width, int Height, Span<uint> Destination)
        {
            if (!CanBlitBitmap(Bitmap) || Width <= 0 || Height <= 0)
                return false;

            if (!Instance.IsRegionMapped(Bitmap.BitsAddress, Bitmap.BitsSize))
                return false;

            for (int Row = 0; Row < Height; Row++)
            {
                Span<uint> Line = Destination.Slice(Row * Width, Width);
                int SourceRow = Y + Row;

                if ((uint)SourceRow >= (uint)Bitmap.Height)
                {
                    Line.Clear();
                    continue;
                }

                int Left = Math.Max(X, 0);
                int Right = Math.Min(X + Width, Bitmap.Width);
                if (Right <= Left)
                {
                    Line.Clear();
                    continue;
                }

                if (Left != X || Right != X + Width)
                    Line.Clear();

                if (!TryReadBitmapRow(Instance, Bitmap, SourceRow, Left, Right - Left, Line.Slice(Left - X)))
                    return false;
            }

            return true;
        }

        internal static bool TryBlitBlockIntoBitmap(BinaryEmulator Instance, in Win32kBitmap Bitmap, int X, int Y, int Width, int Height,
            ReadOnlySpan<uint> Source, int SourceWidth, int SourceHeight, uint Rop, uint PatternPixel, GdiClipRect[] Clip = null)
        {
            if (!CanBlitBitmap(Bitmap) || Width <= 0 || Height <= 0 || SourceWidth <= 0 || SourceHeight <= 0)
                return false;

            if (!Instance.IsRegionMapped(Bitmap.BitsAddress, Bitmap.BitsSize))
                return false;

            int Left = Math.Max(X, 0);
            int Top = Math.Max(Y, 0);
            int Right = Math.Min(X + Width, Bitmap.Width);
            int Bottom = Math.Min(Y + Height, Bitmap.Height);
            if (Right <= Left || Bottom <= Top)
                return true;

            if (Clip == null)
                return BlitRowsIntoBitmap(Instance, Bitmap, X, Y, Width, Height, Source, SourceWidth, SourceHeight, Rop, PatternPixel, Left, Top, Right, Bottom);

            foreach (GdiClipRect Rect in Clip)
            {
                int ClipLeft = Math.Max(Left, Rect.Left);
                int ClipTop = Math.Max(Top, Rect.Top);
                int ClipRight = Math.Min(Right, Rect.Right);
                int ClipBottom = Math.Min(Bottom, Rect.Bottom);
                if (ClipRight <= ClipLeft || ClipBottom <= ClipTop)
                    continue;

                if (!BlitRowsIntoBitmap(Instance, Bitmap, X, Y, Width, Height, Source, SourceWidth, SourceHeight, Rop, PatternPixel, ClipLeft, ClipTop, ClipRight, ClipBottom))
                    return false;
            }

            return true;
        }

        private static bool BlitRowsIntoBitmap(BinaryEmulator Instance, in Win32kBitmap Bitmap, int X, int Y, int Width, int Height,
            ReadOnlySpan<uint> Source, int SourceWidth, int SourceHeight, uint Rop, uint PatternPixel, int Left, int Top, int Right, int Bottom)
        {
            int Span = Right - Left;
            uint Index = (Rop >> 16) & 0xFF;
            bool Copy = Rop == SrcCopyRop;
            bool ReadDestination = !Copy && RopUsesDestination(Rop);

            bool Solid = SourceWidth == 1 && SourceHeight == 1;
            bool Unscaled = SourceWidth == Width;

            uint[] Rented = ArrayPool<uint>.Shared.Rent(Span);
            try
            {
                System.Span<uint> Line = Rented.AsSpan(0, Span);

                if (Solid && !ReadDestination)
                {
                    Line.Fill(Copy ? Source[0] & 0x00FFFFFF : ApplyRop(Index, PatternPixel, Source[0], 0));
                    for (int Row = Top; Row < Bottom; Row++)
                    {
                        if (!TryWriteBitmapRow(Instance, Bitmap, Row, Left, Span, Line))
                            return false;
                    }

                    return true;
                }

                for (int Row = Top; Row < Bottom; Row++)
                {
                    int SourceRow = Solid ? 0 : (int)((long)(Row - Y) * SourceHeight / Height);
                    ReadOnlySpan<uint> SourceLine = Source.Slice(SourceRow * SourceWidth, SourceWidth);

                    if (ReadDestination && !TryReadBitmapRow(Instance, Bitmap, Row, Left, Span, Line))
                        return false;

                    for (int Column = 0; Column < Span; Column++)
                    {
                        int SourceColumn = Solid ? 0 : Unscaled ? Left + Column - X : (int)((long)(Left + Column - X) * SourceWidth / Width);
                        uint Pixel = SourceLine[SourceColumn];
                        Line[Column] = Copy ? Pixel & 0x00FFFFFF : ApplyRop(Index, PatternPixel, Pixel, ReadDestination ? Line[Column] : 0);
                    }

                    if (!TryWriteBitmapRow(Instance, Bitmap, Row, Left, Span, Line))
                        return false;
                }

                return true;
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Rented);
            }
        }

        internal static bool BlitBlockToDc(BinaryEmulator Instance, ulong Hdc, int X, int Y, int Width, int Height,
            ReadOnlySpan<uint> Source, int SourceWidth, int SourceHeight, uint Rop)
        {
            if (Width <= 0 || Height <= 0 || SourceWidth <= 0 || SourceHeight <= 0)
                return false;

            if (Source.Length < SourceWidth * SourceHeight)
                return false;

            if (TryGetDcBitmap(Instance, Hdc, out Win32kBitmap Target) && CanBlitBitmap(Target))
            {
                uint PatternPixel = HostColor.FromColorRef(ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedBrush(Hdc), false).ColorRef);
                Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
                TryGetDcClip(Instance, Hdc, out GdiClipRect[] Clip);
                return TryBlitBlockIntoBitmap(Instance, Target, X + OffsetX, Y + OffsetY, Width, Height, Source, SourceWidth, SourceHeight, Rop, PatternPixel, Clip);
            }

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
                return false;

            // The GUI thread drains the queue later, so it gets rows of its own.
            int Count = SourceWidth * SourceHeight;
            uint[] Owned = ArrayPool<uint>.Shared.Rent(Count);
            Source.Slice(0, Count).CopyTo(Owned);

            // A window has no readable surface, so only a rop that ignores the destination can be resolved.
            if (Rop != SrcCopyRop && !RopUsesDestination(Rop))
            {
                uint Index = (Rop >> 16) & 0xFF;
                uint PatternPixel = HostColor.FromColorRef(ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedBrush(Hdc), false).ColorRef);

                for (int i = 0; i < Count; i++)
                    Owned[i] = ApplyRop(Index, PatternPixel, Owned[i], 0);

                Rop = SrcCopyRop;
            }

            Instance.WinHelper.EnqueueGdiBlit(Hwnd, Hdc, X, Y, X + Width, Y + Height, Owned, SourceWidth, SourceHeight, Rop);
            return true;
        }

        internal static bool BlitBlockToWindow(BinaryEmulator Instance, ulong Hwnd, int X, int Y, int Width, int Height,
            ReadOnlySpan<uint> Source, int SourceWidth, int SourceHeight, uint Rop)
        {
            if (Hwnd == 0 || Width <= 0 || Height <= 0 || SourceWidth <= 0 || SourceHeight <= 0)
                return false;

            if (Source.Length < SourceWidth * SourceHeight)
                return false;

            int Count = SourceWidth * SourceHeight;
            uint[] Owned = ArrayPool<uint>.Shared.Rent(Count);
            Source.Slice(0, Count).CopyTo(Owned);
            Instance.WinHelper.EnqueueGdiBlit(Hwnd, 0, X, Y, X + Width, Y + Height, Owned, SourceWidth, SourceHeight, Rop);
            return true;
        }

        internal static bool TryReadDcBlock(BinaryEmulator Instance, ulong Hdc, int X, int Y, int Width, int Height, Span<uint> Destination)
        {
            if (!TryGetDcBitmap(Instance, Hdc, out Win32kBitmap Source))
                return false;

            Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);
            return TryReadBitmapBlock(Instance, Source, X + OffsetX, Y + OffsetY, Width, Height, Destination);
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

        private readonly struct Win32kSentNotification
        {
            public readonly Win32kMessage Message;
            public readonly uint Sender;
            public readonly int Depth;

            public Win32kSentNotification(in Win32kMessage Message, uint Sender, int Depth)
            {
                this.Message = Message;
                this.Sender = Sender;
                this.Depth = Depth;
            }
        }

        // NT sends these. One overtaken by the activation or focus state is dropped.
        private static void PostNotification(BinaryEmulator Instance, ulong Hwnd, uint Message, ulong WParam, ulong LParam, bool FromHost)
        {
            if (Instance.WinHelper.GetWindow(Hwnd) == null)
                return;

            Win32kState State = GetState(Instance);
            Win32kMessage Notification = new Win32kMessage(Hwnd, Message, WParam, LParam, unchecked((uint)Instance.EmulatedTickCount64), State.CursorScreenX, State.CursorScreenY, 0, true);

            // The callback path is x64 only.
            if (Instance.WinHelper.PointerSize == 8)
            {
                EmulatedThread Thread = Instance.CurrentThread;
                uint Sender = FromHost ? 0 : Thread?.ThreadId ?? 0;
                State.SentNotifications.Add(new Win32kSentNotification(Notification, Sender, GetCallbackDepth(Thread)));
            }
            else
            {
                QueueNotificationMessage(State, Notification);
            }

            Instance.WakeSignal.Bump();
        }

        private static void QueueNotificationMessage(Win32kState State, in Win32kMessage Notification)
        {
            State.MessageQueue.Enqueue(Notification);
            State.QueuedNotifications++;
            if (State.QueuedWakeBitsValid)
                State.QueuedWakeBits |= GetQueuedMessageWakeBits(Notification);
        }

        private static int GetCallbackDepth(EmulatedThread Thread)
        {
            return WinEmulatedThread.TryGetState(Thread)?.UserCallbackFrames.Count ?? 0;
        }

        // True while a procedure runs. The syscall returns Result after the last one.
        internal static bool SendNotifications(BinaryEmulator Instance, ulong Result)
        {
            Win32kState State = GetState(Instance);
            while (TryTakeNotification(Instance, State, false, out Win32kMessage Notification))
            {
                if (InvokeNotification(Instance, State, Notification, 0, Result))
                    return true;
            }

            return false;
        }

        internal static void ReturnAfterNotifications(BinaryEmulator Instance, ulong Result)
        {
            if (!SendNotifications(Instance, Result))
                Instance.SetRawSyscallReturn(Result);
        }

        // NT: xxxReceiveMessages.
        internal static bool ReceiveNotification(BinaryEmulator Instance, ulong SyscallRip)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            while (TryTakeNotification(Instance, State, true, out Win32kMessage Notification))
            {
                if (InvokeNotification(Instance, State, Notification, SyscallRip, null))
                    return true;
            }

            return false;
        }

        // A nested procedure never runs an outer send. Other sends wait for the owner to read its queue.
        private static bool TryTakeNotification(BinaryEmulator Instance, Win32kState State, bool Reading, out Win32kMessage Notification)
        {
            List<Win32kSentNotification> Pending = State.SentNotifications;
            EmulatedThread Thread = Instance.CurrentThread;
            uint ThreadId = Thread?.ThreadId ?? 0;
            int Depth = GetCallbackDepth(Thread);

            for (int i = 0; i < Pending.Count;)
            {
                Win32kSentNotification Candidate = Pending[i];
                if (Instance.WinHelper.GetWindow(Candidate.Message.Hwnd) == null || IsOvertaken(Instance, Candidate.Message))
                {
                    Pending.RemoveAt(i);
                    continue;
                }

                bool Eligible = IsOwnSend(Candidate, ThreadId) ? Candidate.Depth >= Depth : Reading;
                if (Eligible && OwnedByThread(Instance, Candidate.Message.Hwnd, ThreadId))
                {
                    Pending.RemoveAt(i);
                    Notification = Candidate.Message;
                    return true;
                }

                i++;
            }

            Notification = default;
            return false;
        }

        private static bool IsOwnSend(in Win32kSentNotification Notification, uint ThreadId)
        {
            return Notification.Sender != 0 && Notification.Sender == ThreadId;
        }

        private static bool HasIncomingNotification(BinaryEmulator Instance, Win32kState State, uint ThreadId)
        {
            foreach (Win32kSentNotification Candidate in State.SentNotifications)
            {
                if (!IsOwnSend(Candidate, ThreadId)
                    && OwnedByThread(Instance, Candidate.Message.Hwnd, ThreadId)
                    && Instance.WinHelper.GetWindow(Candidate.Message.Hwnd) != null
                    && !IsOvertaken(Instance, Candidate.Message))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool InvokeNotification(BinaryEmulator Instance, Win32kState State, in Win32kMessage Notification, ulong SyscallRetryRip, ulong? Result)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Notification.Hwnd);
            if (InvokeWindowProc(Instance, Notification.Hwnd, Window.WndProc, Notification.Message, Notification.WParam, Notification.LParam,
                SyscallRetryRip: SyscallRetryRip, DeferredSyscallResult: Result))
            {
                return true;
            }

            QueueNotificationMessage(State, Notification);
            return false;
        }

        private static void DropOvertakenNotifications(BinaryEmulator Instance, Win32kState State)
        {
            Queue<Win32kMessage> Queue = State.MessageQueue;
            int Remaining = 0;

            for (int Count = Queue.Count; Count > 0; Count--)
            {
                Win32kMessage Message = Queue.Dequeue();
                if (Message.Notification)
                {
                    if (IsOvertaken(Instance, Message))
                        continue;

                    Remaining++;
                }

                Queue.Enqueue(Message);
            }

            State.QueuedNotifications = Remaining;
        }

        private static bool IsOvertaken(BinaryEmulator Instance, in Win32kMessage Message)
        {
            WinSysHelper Helper = Instance.WinHelper;
            bool Active = Helper.ActiveWindow == Message.Hwnd;

            return Message.Message switch
            {
                WM_ACTIVATE => ((Message.WParam & 0xFFFF) != WA_INACTIVE) != Active,
                WM_NCACTIVATE => (Message.WParam != 0) != Active,
                WM_SETFOCUS => Helper.FocusWindow != Message.Hwnd,
                WM_KILLFOCUS => Helper.FocusWindow == Message.Hwnd,
                WM_ACTIVATEAPP => (Message.WParam != 0) != (Helper.GetForegroundWindow() != 0),
                _ => false,
            };
        }

        internal static bool PostThreadMessage(BinaryEmulator Instance, uint TargetThreadId, uint Message, ulong WParam, ulong LParam)
        {
            return PostMessage(Instance, GetState(Instance), 0, Message, WParam, LParam, TargetThreadId);
        }

        private static bool PostMessage(BinaryEmulator Instance, Win32kState State, ulong Hwnd, uint Message, ulong WParam, ulong LParam, uint TargetThreadId = 0)
        {
            uint Time = unchecked((uint)Instance.EmulatedTickCount64);
            int X = State.CursorScreenX;
            int Y = State.CursorScreenY;

            if (Hwnd == HWND_BROADCAST)
            {
                foreach (ulong TargetHwnd in Instance.WinHelper.TopLevelWindows)
                {
                    if (Instance.WinHelper.GetWindow(TargetHwnd) == null)
                        continue;

                    State.MessageQueue.Enqueue(new Win32kMessage(TargetHwnd, Message, WParam, LParam, Time, X, Y));
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

            State.MessageQueue.Enqueue(new Win32kMessage(Hwnd, Message, WParam, LParam, Time, X, Y, TargetThreadId));
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

        internal static ulong SetTimer(BinaryEmulator Instance, ulong Hwnd, ulong Id, uint Elapse, ulong Proc)
        {
            Win32kState State = GetState(Instance);

            if (Elapse < USER_TIMER_MINIMUM)
                Elapse = USER_TIMER_MINIMUM;
            else if (Elapse > USER_TIMER_MAXIMUM)
                Elapse = USER_TIMER_MAXIMUM;

            if (Hwnd == 0)
                Id = State.NextWindowlessTimerId++;

            Win32kTimer Timer = null;
            foreach (Win32kTimer Candidate in State.Timers)
            {
                if (Candidate.Hwnd == Hwnd && Candidate.Id == Id)
                {
                    Timer = Candidate;
                    break;
                }
            }

            if (Timer == null)
            {
                Timer = new Win32kTimer { Hwnd = Hwnd, Id = Id, ThreadId = Instance.CurrentThread?.ThreadId ?? 0 };
                State.Timers.Add(Timer);
            }

            Timer.Proc = Proc;
            Timer.Elapse = Elapse;
            Timer.Due = Instance.CreateEmulatedDeadlineMilliseconds(Elapse);

            WakeMessageWaiters(Instance);
            return Id;
        }

        internal static bool KillTimer(BinaryEmulator Instance, ulong Hwnd, ulong Id)
        {
            Win32kState State = GetState(Instance);
            uint ThreadId = Instance.CurrentThread?.ThreadId ?? 0;

            for (int i = 0; i < State.Timers.Count; i++)
            {
                if (State.Timers[i].Hwnd != Hwnd || State.Timers[i].Id != Id)
                    continue;

                if (!TimerOwnedByThread(Instance, State.Timers[i], ThreadId))
                    return false;

                State.Timers.RemoveAt(i);
                return true;
            }

            return false;
        }

        // A windowless timer belongs to the thread that set it, one on a window to the thread that owns it.
        private static bool TimerOwnedByThread(BinaryEmulator Instance, Win32kTimer Timer, uint ThreadId)
        {
            return Timer.Hwnd != 0
                ? OwnedByThread(Instance, Timer.Hwnd, ThreadId)
                : ThreadId == 0 || Timer.ThreadId == 0 || Timer.ThreadId == ThreadId;
        }

        // A deadline for a timer the caller cannot consume parks it on an expiry it never clears.
        internal static long GetNextTimerDue(BinaryEmulator Instance, ulong HwndFilter, uint ThreadId, uint MinMessage, uint MaxMessage)
        {
            if (!MessageInFilter(WM_TIMER, MinMessage, MaxMessage))
                return -1;

            Win32kState State = GetState(Instance);
            DropTimersOfGoneWindows(Instance, State);

            long Earliest = -1;
            foreach (Win32kTimer Timer in State.Timers)
            {
                if (HwndFilter != 0 && Timer.Hwnd != HwndFilter)
                    continue;

                bool Owned = Timer.Hwnd != 0
                    ? OwnedByThread(Instance, Timer.Hwnd, ThreadId)
                    : ThreadId == 0 || Timer.ThreadId == 0 || Timer.ThreadId == ThreadId;

                if (!Owned)
                    continue;

                if (Earliest == -1 || Timer.Due < Earliest)
                    Earliest = Timer.Due;
            }

            return Earliest;
        }

        // A parked thread carries the deadline it was given, so each one is re-armed on the timer it can take.
        private static void WakeMessageWaiters(BinaryEmulator Instance)
        {
            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread == null || !Thread.WaitActive || Thread.State != EmulatedThreadState.Waiting)
                    continue;

                WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
                if (State == null || (!State.GetMessageWaitActive && !State.WaitMessageActive))
                    continue;

                Thread.WaitDeadline = State.GetMessageWaitActive
                    ? GetNextTimerDue(Instance, State.GetMessageHwndFilter, Thread.ThreadId, State.GetMessageMinMessage, State.GetMessageMaxMessage)
                    : GetNextTimerDue(Instance, 0, Thread.ThreadId, 0, 0);
            }

            Instance.WakeSignal.Bump();
        }

        private static void DropTimersOfGoneWindows(BinaryEmulator Instance, Win32kState State)
        {
            for (int i = State.Timers.Count - 1; i >= 0; i--)
            {
                ulong Hwnd = State.Timers[i].Hwnd;
                if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
                    State.Timers.RemoveAt(i);
            }
        }

        private static Win32kTimer FindDueTimer(BinaryEmulator Instance, Win32kState State, ulong HwndFilter, uint ThreadId)
        {
            if (State.Timers.Count == 0)
                return null;

            DropTimersOfGoneWindows(Instance, State);

            long Now = Instance.EmulatedTickCount64;
            Win32kTimer Earliest = null;

            foreach (Win32kTimer Timer in State.Timers)
            {
                if (HwndFilter != 0 && Timer.Hwnd != HwndFilter)
                    continue;

                if (!TimerOwnedByThread(Instance, Timer, ThreadId))
                    continue;

                if (Timer.Due > Now)
                    continue;

                if (Earliest == null || Timer.Due < Earliest.Due)
                    Earliest = Timer;
            }

            return Earliest;
        }

        internal static bool TryGetMessage(BinaryEmulator Instance, ulong HwndFilter, uint MinMessage, uint MaxMessage, uint WakeMask, bool Remove, uint ThreadId, out Win32kMessage Message)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            if (State.QueuedNotifications != 0)
                DropOvertakenNotifications(Instance, State);

            int Index = 0;
            foreach (Win32kMessage Candidate in State.MessageQueue)
            {
                if ((GetQueuedMessageWakeBits(Candidate) & WakeMask) != 0
                    && MatchesFilter(Instance, Candidate, HwndFilter, MinMessage, MaxMessage, ThreadId))
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

            // NT hands out WM_PAINT only when the queue is empty, and keeps doing so until validation.
            if ((WakeMask & QS_PAINT) != 0 && MessageInFilter(WM_PAINT, MinMessage, MaxMessage))
            {
                WinWindow Dirty = FindDirtyWindow(Instance, HwndFilter, ThreadId);
                if (Dirty != null)
                {
                    // NT: xxxDoPaint clears WFUPDATEDIRTY.
                    Message = SynthesizeMessage(Instance, State, Dirty.Hwnd, WM_PAINT, 0, 0);
                    Dirty.UpdateDirty = false;
                    if (Remove)
                        Dirty.Dirty = false;

                    return true;
                }
            }

            if (State.QuitPosted && (WakeMask & QS_POSTMESSAGE) != 0)
            {
                Message = SynthesizeMessage(Instance, State, 0, WM_QUIT, State.QuitExitCode, 0);
                if (Remove)
                    State.QuitPosted = false;
                return true;
            }

            // WM_TIMER is the lowest priority message and is synthesized, not queued.
            if ((WakeMask & QS_TIMER) != 0 && MessageInFilter(WM_TIMER, MinMessage, MaxMessage))
            {
                Win32kTimer Timer = FindDueTimer(Instance, State, HwndFilter, ThreadId);
                if (Timer != null)
                {
                    Message = SynthesizeMessage(Instance, State, Timer.Hwnd, WM_TIMER, Timer.Id, Timer.Proc);
                    if (Remove)
                        Timer.Due = Instance.CreateEmulatedDeadlineMilliseconds(Timer.Elapse);

                    return true;
                }
            }

            Message = default;
            return false;
        }

        private static Win32kMessage SynthesizeMessage(BinaryEmulator Instance, Win32kState State, ulong Hwnd, uint Message, ulong WParam, ulong LParam)
        {
            return new Win32kMessage(Hwnd, Message, WParam, LParam, unchecked((uint)Instance.EmulatedTickCount64), State.CursorScreenX, State.CursorScreenY);
        }

        private static bool MessageInFilter(uint Message, uint MinMessage, uint MaxMessage)
        {
            return (MinMessage == 0 && MaxMessage == 0) || (Message >= MinMessage && Message <= MaxMessage);
        }

        // win32kfull!xxxDoPaint. Only the first dirty window found is painted, and only when the filter accepts it.
        private static WinWindow FindDirtyWindow(BinaryEmulator Instance, ulong HwndFilter, uint ThreadId)
        {
            ulong Locked = GetState(Instance).UpdateLockWindow;
            WinWindow Found = FindDirtyWindowAmong(Instance, Instance.WinHelper.TopLevelWindows, true, ThreadId, Locked, 0);

            if (Found == null || HwndFilter == 0 || Found.Hwnd == HwndFilter)
                return Found;

            const uint WS_CHILD = 0x40000000;
            const uint WS_POPUP = 0x80000000;

            for (WinWindow Window = Found; Window != null && (Window.Style & (WS_CHILD | WS_POPUP)) == WS_CHILD;)
            {
                if (Window.ParentHwnd == HwndFilter)
                    return Found;

                Window = Instance.WinHelper.GetWindow(Window.ParentHwnd);
            }

            return null;
        }

        // win32kfull!xxxInternalDoPaint. Another thread's window is skipped but not its children, and a transparent
        // window yields to a sibling below it.
        private static WinWindow FindDirtyWindowAmong(BinaryEmulator Instance, List<ulong> Siblings, bool EndIsTop, uint ThreadId, ulong Locked, int Depth)
        {
            if (Depth >= MaxWindowTreeDepth)
                return null;

            int Count = Siblings.Count;

            for (int n = 0; n < Count; n++)
            {
                WinWindow Window = Instance.WinHelper.GetWindow(Siblings[EndIsTop ? Count - 1 - n : n]);
                if (Window == null || Window.Destroyed || !Window.Visible)
                    continue;

                if (NeedsPaint(Window, ThreadId, Locked))
                {
                    if ((Window.ExStyle & WindowExStyleTransparent) == 0)
                        return Window;

                    for (int k = n + 1; k < Count; k++)
                    {
                        WinWindow Below = Instance.WinHelper.GetWindow(Siblings[EndIsTop ? Count - 1 - k : k]);
                        if (Below != null && !Below.Destroyed && Below.Visible && NeedsPaint(Below, ThreadId, Locked) && (Below.ExStyle & WindowExStyleTransparent) == 0)
                            return Below;
                    }

                    return Window;
                }

                WinWindow Child = FindDirtyWindowAmong(Instance, Window.Children, false, ThreadId, Locked, Depth + 1);
                if (Child != null)
                    return Child;
            }

            return null;
        }

        private static bool NeedsPaint(WinWindow Window, uint ThreadId, ulong Locked)
        {
            return Window.Dirty && Window.Hwnd != Locked
                && (ThreadId == 0 || Window.OwnerThreadId == 0 || Window.OwnerThreadId == ThreadId);
        }

        internal static bool HasQueuedInputEvent(BinaryEmulator Instance, uint WakeMask, uint ThreadId)
        {
            return GetQueuedWakeBits(Instance, WakeMask, ThreadId) != 0;
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

        // A thread told about work it may not dequeue wakes, finds nothing, and parks again at once.
        internal static uint GetQueuedWakeBits(BinaryEmulator Instance, uint WakeMask, uint ThreadId)
        {
            DrainHostEvents(Instance);

            if (WakeMask == 0)
                return 0;

            Win32kState State = GetState(Instance);
            uint Queued;

            if (ThreadId != 0)
            {
                Queued = 0;
                foreach (Win32kMessage Candidate in State.MessageQueue)
                {
                    if (OwnedByThread(Instance, Candidate, ThreadId))
                        Queued |= GetQueuedMessageWakeBits(Candidate);
                }
            }
            else
            {
                if (!State.QueuedWakeBitsValid)
                {
                    uint All = 0;
                    foreach (Win32kMessage Candidate in State.MessageQueue)
                        All |= GetQueuedMessageWakeBits(Candidate);

                    State.QueuedWakeBits = All;
                    State.QueuedWakeBitsValid = true;
                }

                Queued = State.QueuedWakeBits;
            }

            uint Bits = State.QuitPosted ? Queued | QS_POSTMESSAGE : Queued;
            if ((WakeMask & QS_SENDMESSAGE) != 0 && HasIncomingNotification(Instance, State, ThreadId))
                Bits |= QS_SENDMESSAGE;

            if ((WakeMask & QS_PAINT) != 0 && FindDirtyWindow(Instance, 0, ThreadId) != null)
                Bits |= QS_PAINT;

            if ((WakeMask & QS_TIMER) != 0 && FindDueTimer(Instance, State, 0, ThreadId) != null)
                Bits |= QS_TIMER;

            return Bits & WakeMask;
        }

        private static uint GetMessageWakeBits(uint Message)
        {
            if (Message >= WM_LBUTTONDOWN && Message <= WM_MOUSEHWHEEL)
                return QS_MOUSEBUTTON;

            switch (Message)
            {
                case WM_PAINT:
                    return QS_PAINT;
                case WM_TIMER:
                    return QS_TIMER;
                case WM_INPUT:
                    return QS_RAWINPUT;
                case WM_MOUSEMOVE:
                    return QS_MOUSEMOVE;
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

        internal static bool WriteMessage(BinaryEmulator Instance, ulong Address, Win32kMessage Message, WindowsThreadState Reader)
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

            if (!Instance.WriteMemory(Address, Buffer.Slice(0, Size)))
                return false;

            if (Reader != null)
            {
                Reader.LastMessageX = Message.X;
                Reader.LastMessageY = Message.Y;
                Reader.LastMessageTime = Message.Time;
            }

            return true;
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

        // Scratch list. Do not hold it across a guest call.
        internal static List<GdiClipRect> GetPaintArea(BinaryEmulator Instance, WinWindow Window, out GdiClipRect Bounds)
        {
            Win32kState State = GetState(Instance);
            List<GdiClipRect> Area = State.PaintArea;
            GetUpdateRegion(Instance, Window, Area);

            GdiClipRect[] Visible = Instance.WinHelper.GetWindowClip(Window.Hwnd);
            if (Visible != null)
            {
                List<GdiClipRect> Shown = State.DcArea;
                Shown.Clear();
                AddSurfaceRectsAsClient(Instance, Window.Hwnd, Visible, Shown);
                IntersectRegion(Instance, Area, CollectionsMarshal.AsSpan(Shown));
            }

            GetRegionBounds(Area, out Bounds);
            return Area;
        }

        private static int PaintStructEraseOffset(bool Wide) => Wide ? 0x08 : 0x04;

        internal static bool WritePaintStruct(BinaryEmulator Instance, ulong PaintStructPtr, ulong Hdc, in GdiClipRect Area, bool Erase)
        {
            bool Wide = Is64(Instance);
            int Size = Wide ? PAINTSTRUCT64_SIZE : PAINTSTRUCT32_SIZE;
            if (PaintStructPtr == 0 || !Instance.IsRegionMapped(PaintStructPtr, (uint)Size))
                return false;

            int RectOffset = PaintStructEraseOffset(Wide) + 4;
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((ulong)Size);
            Buffer.Clear();
            if (Wide)
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Hdc);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), (uint)Hdc);

            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset - 4, 4), Erase ? 1 : 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 0, 4), Area.Left);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 4, 4), Area.Top);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 8, 4), Area.Right);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(RectOffset + 12, 4), Area.Bottom);
            return Instance.WriteMemory(PaintStructPtr, Buffer.Slice(0, Size));
        }

        // NT: a zero answer leaves the erase to the paint, and PAINTSTRUCT.fErase says so.
        internal static bool SendEraseBackground(BinaryEmulator Instance, WinWindow Window, WinPaintBegin Paint)
        {
            return IsOwnedByCurrentThread(Instance, Window)
                && InvokeWindowProc(Instance, Window.Hwnd, Window.WndProc, WM_ERASEBKGND, Paint.Hdc, 0, PaintBegin: Paint);
        }

        internal static ulong FinishBeginPaint(BinaryEmulator Instance, WinPaintBegin Paint, ulong Erased)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Paint.Hwnd);
            if (Window != null)
                Window.BackgroundUnerased = Erased == 0;

            WritePaintErase(Instance, Paint.PaintStruct, Erased == 0);
            return Paint.Hdc;
        }

        internal static void WritePaintErase(BinaryEmulator Instance, ulong PaintStructPtr, bool Erase)
        {
            Span<byte> Value = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(Value, Erase ? 1 : 0);
            Instance.WriteMemory(PaintStructPtr + (ulong)PaintStructEraseOffset(Is64(Instance)), Value);
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

        /// <summary>
        /// Writes a WNDCLASSEXW in the layout of the guest architecture.
        /// </summary>
        internal static bool TryWriteWindowClass(BinaryEmulator Instance, ulong Address, WinWindowClass Class)
        {
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (Address == 0 || Class == null || !Instance.IsRegionMapped(Address, WindowClassSize(Instance)))
                return false;

            return Instance._emulator.WriteMemory(Address + 0, WindowClassSize(Instance))
                && Instance._emulator.WriteMemory(Address + 4, Class.Style)
                && Instance.WinHelper.WritePointer(Address + 8, Class.WndProc)
                && Instance._emulator.WriteMemory(Address + 8 + PointerSize, (uint)Class.ClassExtraBytes)
                && Instance._emulator.WriteMemory(Address + 12 + PointerSize, (uint)Class.WindowExtraBytes)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize, Class.InstanceHandle)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize * 2, Class.IconHandle)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize * 3, Class.CursorHandle)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize * 4, Class.BackgroundBrush)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize * 5, 0)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize * 6, Class.Atom)
                && Instance.WinHelper.WritePointer(Address + 16 + PointerSize * 7, Class.SmallIconHandle);
        }

        internal static ulong DispatchMessage(BinaryEmulator Instance, Win32kMessage Message, out bool Deferred)
        {
            Deferred = false;

            WinWindow Window = Message.Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Message.Hwnd);
            if (Message.Hwnd != 0 && Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                return 0;
            }

            if (Window == null)
                return 0;

            return DefaultWindowProc(Instance, Window, Message.Message, Message.WParam, Message.LParam, false, out Deferred);
        }

        private const int MaxHostInputEventsPerDrain = 64;

        private static void DrainHostEvents(BinaryEmulator Instance)
        {
            // Nothing can be delivered before the guest makes a window visible, and the host queue must survive
            // until then: consuming the repaint flag (or draining input) here would discard the only events a
            // thread parked in MsgWaitForMultipleObjectsEx can ever be woken by.
            ulong TopVisible = Instance.WinHelper.GetTopVisibleWindow();
            if (TopVisible == 0)
                return;

            ulong Presented = Instance.WinHelper.PresentedWindow;
            if (Presented == 0)
                Presented = Instance.WinHelper.GetForegroundWindow();
            if (Presented == 0)
                Presented = TopVisible;

            Win32kDpi.DrainHostDpiChange(Instance);

            // The host surface holds no backing store, so a host repaint has erased every control with it.
            bool Present = false;
            if (HostEventQueue.ConsumeRepaint())
            {
                InvalidateWholeWindow(Instance, Instance.WinHelper.GetWindow(Presented));
                Present = true;
            }

            while (HostEventQueue.TryTakeRepaint(out ulong RepaintWindow))
            {
                WinWindow Repainted = Instance.WinHelper.GetWindow(RepaintWindow);
                if (Repainted != null)
                {
                    InvalidateWholeWindow(Instance, Repainted);
                    Present = true;
                }
            }

            Win32kState State = GetState(Instance);
            for (int i = 0; i < MaxHostInputEventsPerDrain; i++)
            {
                if (!HostEventQueue.TryDequeue(out HostEventQueue.HostEvent Event))
                    break;

                uint Message = Event.Message;
                ulong WParam = Event.WParam;
                ulong LParam = Event.LParam;
                ulong Source = Event.Window;

                ulong Root = Presented;
                if (Source != 0)
                {
                    if (Instance.WinHelper.GetWindow(Source) == null)
                        continue;

                    Root = Source;
                }

                if (Message == HostEventQueue.RawMouseMotion)
                {
                    ulong RawTarget = Instance.WinHelper.GetForegroundWindow();
                    Win32kRawInput.DeliverHostRawMouse(Instance, RawTarget != 0 ? RawTarget : Root, unchecked((int)(uint)WParam), unchecked((int)(uint)LParam));
                    continue;
                }

                if (Message == WM_SETFOCUS || Message == WM_KILLFOCUS)
                {
                    ApplyHostFocus(Instance, State, Source, Message == WM_SETFOCUS);
                    continue;
                }

                TrackKeyState(State, Message, WParam, LParam);

                if (Message >= WM_MOUSEMOVE && Message <= WM_XBUTTONUP && Message != WM_MOUSEWHEEL)
                {
                    LParam = TrackHostPointer(Instance, State, Root, in Event);

                    if (State.CursorHiddenWhileTyping)
                    {
                        State.CursorHiddenWhileTyping = false;
                        ApplyCursorVisibility(Instance, State);
                    }
                }
                else if (Message == WM_SIZE || Message == WM_MOVE)
                {
                    bool Changed = Message == WM_SIZE
                        ? ApplyHostResize(Instance, Root, WParam, LParam)
                        : ApplyHostMove(Instance, Root, LParam);

                    if (Changed)
                        QueueWindowPosChanged(Instance, State, Root, Message == WM_SIZE ? SwpNoMove | SwpNoClientMove : SwpNoSize | SwpNoClientSize);

                    Present = true;

                    // NT delivers WM_SIZE and WM_MOVE from DefWindowProc's answer to WM_WINDOWPOSCHANGED.
                    if (Changed && Instance.WinHelper.PointerSize == 8)
                        continue;
                }

                if (Win32kRawInput.DeliverHostEvent(Instance, Root, Message, WParam, LParam))
                {
                    ulong Target = ResolveInputTarget(Instance, Root, Message, ref LParam);
                    PostMessage(Instance, Target, Message, WParam, LParam);

                    if (State.MouseInPointer)
                        PostPointerMessage(Instance, State, Target, Message, WParam);
                }
            }

            if (Present)
                Instance.WinHelper.PresentDesktop();
        }

        // The host window can lag behind a guest move, so the point goes through the screen.
        private static ulong TrackHostPointer(BinaryEmulator Instance, Win32kState State, ulong Root, in HostEventQueue.HostEvent Event)
        {
            GetClientOrigin(Instance, Instance.WinHelper.GetWindow(Root), out int GuestX, out int GuestY);

            int ScreenX = (short)(Event.LParam & 0xFFFF) + (Event.HasOrigin ? Event.OriginX : GuestX);
            int ScreenY = (short)((Event.LParam >> 16) & 0xFFFF) + (Event.HasOrigin ? Event.OriginY : GuestY);
            State.CursorScreenX = ScreenX;
            State.CursorScreenY = ScreenY;

            return WinSysHelper.PackCoordinates(ScreenX - GuestX, ScreenY - GuestY);
        }

        private const uint SwpPositionFlags = SwpNoSize | SwpNoMove | SwpNoClientSize | SwpNoClientMove;

        private static void QueueWindowPosChanged(BinaryEmulator Instance, Win32kState State, ulong Hwnd, uint Flags)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return;

            if (!Window.PendingWindowPosChanged)
            {
                Window.PendingWindowPosChanged = true;
                Window.PendingWindowPosFlags = SwpPositionFlags;
                State.PendingWindowPosChanged.Enqueue(Hwnd);
                Instance.WakeSignal.Bump();
            }

            Window.PendingWindowPosFlags &= Flags | ~SwpPositionFlags;
        }

        private const byte VkLButton = 0x01;
        private const byte VkRButton = 0x02;
        private const byte VkMButton = 0x04;
        private const byte VkXButton1 = 0x05;
        private const uint KeyLParamExtended = 0x01000000;

        private static void TrackKeyState(Win32kState State, uint Message, ulong WParam, ulong LParam)
        {
            switch (Message)
            {
                case WM_KEYDOWN:
                case WM_SYSKEYDOWN:
                {
                    byte Vk = (byte)WParam;
                    if (State.KeyDownMessage[Vk] == 0)
                        State.KeysHeld++;

                    State.KeyDownMessage[Vk] = (byte)(Message == WM_SYSKEYDOWN ? 2 : 1);
                    SetKeyDown(State, Vk, true);
                    SetKeyDown(State, SideKey(Vk, LParam), true);
                    return;
                }

                case WM_KEYUP:
                case WM_SYSKEYUP:
                {
                    byte Vk = (byte)WParam;
                    if (State.KeyDownMessage[Vk] != 0)
                        State.KeysHeld--;

                    State.KeyDownMessage[Vk] = 0;
                    SetKeyDown(State, Vk, false);
                    SetKeyDown(State, SideKey(Vk, LParam), false);
                    return;
                }

                case WM_LBUTTONDOWN: SetKeyDown(State, VkLButton, true); return;
                case WM_LBUTTONUP: SetKeyDown(State, VkLButton, false); return;
                case WM_RBUTTONDOWN: SetKeyDown(State, VkRButton, true); return;
                case WM_RBUTTONUP: SetKeyDown(State, VkRButton, false); return;
                case WM_MBUTTONDOWN: SetKeyDown(State, VkMButton, true); return;
                case WM_MBUTTONUP: SetKeyDown(State, VkMButton, false); return;
                case WM_XBUTTONDOWN: SetKeyDown(State, XButtonKey(WParam), true); return;
                case WM_XBUTTONUP: SetKeyDown(State, XButtonKey(WParam), false); return;
            }
        }

        private static byte XButtonKey(ulong WParam)
        {
            return (byte)(VkXButton1 + (((WParam >> 16) & 0xFFFF) == 2 ? 1 : 0));
        }

        // WM_KEYDOWN names the unsided modifier. win32k also holds the side the scan code names.
        private static byte SideKey(byte Vk, ulong LParam)
        {
            byte ScanCode = (byte)((LParam >> 16) & 0xFF);
            bool Extended = (LParam & KeyLParamExtended) != 0;

            for (int i = 0; i < KeyMappings.Length; i++)
            {
                Win32kKeyMapping Mapping = KeyMappings[i];
                if (Mapping.ScanCode != ScanCode || Mapping.Extended != Extended || Mapping.VirtualKey != Vk)
                    continue;

                return Mapping.SidedVirtualKey == Vk ? (byte)0 : Mapping.SidedVirtualKey;
            }

            return 0;
        }

        private static void SetKeyDown(Win32kState State, byte Vk, bool Down)
        {
            if (Vk == 0)
                return;

            byte Previous = State.KeyState[Vk];
            if (!Down)
            {
                State.KeyState[Vk] = (byte)(Previous & 0x01);
                return;
            }

            if ((Previous & 0x80) != 0)
                return;

            State.KeyState[Vk] = (byte)(0x80 | ((Previous & 0x01) ^ 0x01));
            State.KeyPressedSinceQuery[Vk] = 1;
        }

        internal static ulong GetKeyState(BinaryEmulator Instance, byte Vk)
        {
            DrainHostEvents(Instance);

            byte Value = GetState(Instance).KeyState[Vk];
            
            // A held key reads 0xFF80, matching what user32 builds from its own cache.
            return (ulong)(((Value & 0x80) != 0 ? 0xFF80 : 0) | (Value & 0x01));
        }

        internal static ulong GetAsyncKeyState(BinaryEmulator Instance, byte Vk)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            ulong Result = (ulong)(((State.KeyState[Vk] & 0x80) != 0 ? 0x8000 : 0) | State.KeyPressedSinceQuery[Vk]);
            State.KeyPressedSinceQuery[Vk] = 0;
            return Result;
        }

        internal static bool GetMouseInPointer(BinaryEmulator Instance)
        {
            return GetState(Instance).MouseInPointer;
        }

        internal const uint PointerIdMouse = 1;
        internal const uint PointerTypeMouse = 4;

        private const uint PointerFlagNew = 0x00000001;
        private const uint PointerFlagInRange = 0x00000002;
        private const uint PointerFlagInContact = 0x00000004;
        private const uint PointerFlagFirstButton = 0x00000010;
        private const uint PointerFlagSecondButton = 0x00000020;
        private const uint PointerFlagThirdButton = 0x00000040;
        private const uint PointerFlagPrimary = 0x00002000;
        private const uint PointerFlagConfidence = 0x00004000;
        private const uint PointerFlagDown = 0x00010000;
        private const uint PointerFlagUpdate = 0x00020000;
        private const uint PointerFlagUp = 0x00040000;

        private const uint PointerChangeNone = 0;
        private const uint PointerChangeFirstDown = 1;
        private const uint PointerChangeFirstUp = 2;
        private const uint PointerChangeSecondDown = 3;
        private const uint PointerChangeSecondUp = 4;
        private const uint PointerChangeThirdDown = 5;
        private const uint PointerChangeThirdUp = 6;

        // While mouse-in-pointer is on, Windows raises both messages.
        private static void PostPointerMessage(BinaryEmulator Instance, Win32kState State, ulong Target, uint Message, ulong WParam)
        {
            uint PointerMessage;
            uint Change = PointerChangeNone;
            uint Buttons = State.PointerFlags & (PointerFlagFirstButton | PointerFlagSecondButton | PointerFlagThirdButton);

            switch (Message)
            {
                case WM_MOUSEMOVE:
                    PointerMessage = WM_POINTERUPDATE;
                    break;
                case WM_LBUTTONDOWN:
                    PointerMessage = WM_POINTERDOWN;
                    Buttons |= PointerFlagFirstButton;
                    Change = PointerChangeFirstDown;
                    break;
                case WM_LBUTTONUP:
                    PointerMessage = WM_POINTERUP;
                    Buttons &= ~PointerFlagFirstButton;
                    Change = PointerChangeFirstUp;
                    break;
                case WM_RBUTTONDOWN:
                    PointerMessage = WM_POINTERUPDATE;
                    Buttons |= PointerFlagSecondButton;
                    Change = PointerChangeSecondDown;
                    break;
                case WM_RBUTTONUP:
                    PointerMessage = WM_POINTERUPDATE;
                    Buttons &= ~PointerFlagSecondButton;
                    Change = PointerChangeSecondUp;
                    break;
                case WM_MBUTTONDOWN:
                    PointerMessage = WM_POINTERUPDATE;
                    Buttons |= PointerFlagThirdButton;
                    Change = PointerChangeThirdDown;
                    break;
                case WM_MBUTTONUP:
                    PointerMessage = WM_POINTERUPDATE;
                    Buttons &= ~PointerFlagThirdButton;
                    Change = PointerChangeThirdUp;
                    break;
                default:
                    return;
            }

            if (Instance.WinHelper.GetWindow(Target) == null)
                return;

            State.PointerScreenX = State.CursorScreenX;
            State.PointerScreenY = State.CursorScreenY;
            State.PointerTargetHwnd = Target;
            State.PointerButtonChange = Change;
            State.PointerFrameId++;

            uint Flags = PointerFlagInRange | PointerFlagPrimary | PointerFlagConfidence | Buttons;
            if (Buttons != 0)
                Flags |= PointerFlagInContact;

            Flags |= PointerMessage switch
            {
                WM_POINTERDOWN => PointerFlagDown,
                WM_POINTERUP => PointerFlagUp,
                _ => PointerFlagUpdate,
            };

            if (State.PointerFrameId == 1)
                Flags |= PointerFlagNew;

            State.PointerFlags = Flags;

            ulong PointerWParam = PointerIdMouse | ((ulong)(ushort)(Flags & 0xFFFF) << 16);
            ulong PointerLParam = (ulong)(uint)((State.PointerScreenY << 16) | (State.PointerScreenX & 0xFFFF));
            PostMessage(Instance, Target, PointerMessage, PointerWParam, PointerLParam);
        }

        internal static bool TryWritePointerInfo(BinaryEmulator Instance, uint PointerId, Span<byte> Buffer)
        {
            Win32kState State = GetState(Instance);
            if (PointerId != PointerIdMouse || Buffer.Length < 0x60)
                return false;

            Buffer.Slice(0, 0x60).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), PointerTypeMouse);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), PointerIdMouse);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), State.PointerFrameId);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x0C, 4), State.PointerFlags);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), Win32kRawInput.GetDevice(0).Handle);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), State.PointerTargetHwnd);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x20, 4), State.PointerScreenX);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x24, 4), State.PointerScreenY);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x30, 4), State.PointerScreenX);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x34, 4), State.PointerScreenY);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x40, 4), (uint)Environment.TickCount);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x44, 4), 1);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x50, 8), (ulong)System.Diagnostics.Stopwatch.GetTimestamp());
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x58, 4), State.PointerButtonChange);
            return true;
        }

        internal static void SetMouseInPointer(BinaryEmulator Instance, bool Enabled)
        {
            GetState(Instance).MouseInPointer = Enabled;
        }

        internal static void CopyKeyboardState(BinaryEmulator Instance, Span<byte> Destination)
        {
            DrainHostEvents(Instance);

            GetState(Instance).KeyState.AsSpan().CopyTo(Destination);
        }

        // A key released while the window is not focused reports no key up, so held keys are released here.
        private static void ApplyHostFocus(BinaryEmulator Instance, Win32kState State, ulong Window, bool Focused)
        {
            if (Focused)
            {
                State.HostFocused = true;
                ApplyHostCursorClip(Instance, State);

                WinWindow Target = Instance.WinHelper.GetWindow(Window);
                Target ??= Instance.WinHelper.GetWindow(State.LastActiveWindow);
                Target ??= Instance.WinHelper.GetWindow(Instance.WinHelper.PresentedWindow);
                Target ??= Instance.WinHelper.GetWindow(Instance.WinHelper.GetTopVisibleWindow());

                if (Target != null)
                    ActivateWindow(Instance, Target, true);

                return;
            }

            if (!State.HostFocused)
                return;

            State.HostFocused = false;
            ulong Active = Instance.WinHelper.ActiveWindow;
            ReleaseHeldKeys(Instance, State, Active != 0 ? Active : Window);
            DeactivateApplication(Instance, true);
        }

        internal static bool CanActivateImplicitly(WinWindow Window)
        {
            const uint WS_CHILD = 0x40000000;
            const uint WS_EX_NOACTIVATE = 0x08000000;

            return Window != null
                && !Window.Destroyed
                && Window.ParentHwnd == 0
                && Window.Hwnd != Win32kMessageOnlyParent.HwndMessage
                && (Window.Style & (WS_CHILD | WindowStyleDisabled)) == 0
                && (Window.ExStyle & WS_EX_NOACTIVATE) == 0;
        }

        private static ulong MinimizedFlag(WinWindow Window) => Window.Minimized ? 0x10000UL : 0;

        /// <summary>
        /// NT: xxxActivateWindow. The messages are queued in the order NT sends them.
        /// </summary>
        internal static void ActivateWindow(BinaryEmulator Instance, WinWindow Window, bool FromHost)
        {
            WinSysHelper Helper = Instance.WinHelper;
            Window = Helper.GetRootWindow(Window);
            if (Window == null || Window.Destroyed)
                return;

            ulong Hwnd = Window.Hwnd;
            ulong Previous = Helper.ActiveWindow;
            bool ApplicationActive = Helper.GetForegroundWindow() != 0;
            if (Previous == Hwnd && ApplicationActive)
                return;

            WinWindow Old = Previous != Hwnd ? Helper.GetWindow(Previous) : null;
            if (Old != null)
            {
                PostNotification(Instance, Previous, WM_NCACTIVATE, 0, 0, FromHost);
                PostNotification(Instance, Previous, WM_ACTIVATE, WA_INACTIVE | MinimizedFlag(Old), Hwnd, FromHost);
            }

            Helper.RaiseActivatedWindow(Window);

            if (!ApplicationActive)
                PostActivateApp(Instance, true, FromHost);

            Helper.ActiveWindow = Hwnd;
            Helper.ForegroundWindow = Hwnd;
            GetState(Instance).LastActiveWindow = Hwnd;

            PostNotification(Instance, Hwnd, WM_NCACTIVATE, 1, 0, FromHost);
            PostNotification(Instance, Hwnd, WM_ACTIVATE, WA_ACTIVE | MinimizedFlag(Window), Old != null ? Previous : 0, FromHost);
            MoveFocus(Instance, Window.Minimized ? 0 : Hwnd, FromHost);

            Helper.SetThreadWindowContext(Window);
            Helper.PublishForegroundWindow();

            if (!FromHost)
                Helper.RequestHostActivation(Hwnd);

            Helper.PresentDesktop();
        }

        internal static void DeactivateApplication(BinaryEmulator Instance, bool FromHost)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong Previous = Helper.ActiveWindow;
            if (Previous == 0 && Helper.ForegroundWindow == 0)
                return;

            WinWindow Old = Helper.GetWindow(Previous);
            if (Old != null)
            {
                PostNotification(Instance, Previous, WM_NCACTIVATE, 0, 0, FromHost);
                PostNotification(Instance, Previous, WM_ACTIVATE, WA_INACTIVE | MinimizedFlag(Old), 0, FromHost);
            }

            PostActivateApp(Instance, false, FromHost);
            MoveFocus(Instance, 0, FromHost);

            Helper.ActiveWindow = 0;
            Helper.ForegroundWindow = 0;
            Helper.PublishFocusState(0, 0);
            Helper.PublishForegroundWindow();
        }

        /// <summary>
        /// NT: activation goes to the owner, else to the next window below that can take it.
        /// </summary>
        internal static void ActivateNextWindow(BinaryEmulator Instance, WinWindow Leaving)
        {
            WinSysHelper Helper = Instance.WinHelper;
            WinWindow Next = null;

            WinWindow Owner = Helper.GetWindow(Leaving.OwnerHwnd);
            if (IsActivationCandidate(Owner, Leaving))
            {
                Next = Owner;
            }
            else
            {
                List<ulong> TopLevel = Helper.TopLevelWindows;
                int At = TopLevel.IndexOf(Leaving.Hwnd);
                for (int i = (At < 0 ? TopLevel.Count : At) - 1; i >= 0 && Next == null; i--)
                {
                    WinWindow Candidate = Helper.GetWindow(TopLevel[i]);
                    if (IsActivationCandidate(Candidate, Leaving))
                        Next = Candidate;
                }
            }

            if (Next != null)
                ActivateWindow(Instance, Next, false);
            else
                DeactivateApplication(Instance, false);
        }

        private static bool IsActivationCandidate(WinWindow Window, WinWindow Leaving)
        {
            return Window != null
                && Window != Leaving
                && Window.Visible
                && !Window.Minimized
                && (Window.ExStyle & WindowExStyleToolWindow) == 0
                && CanActivateImplicitly(Window);
        }

        // NT: hidden windows get it too.
        private static void PostActivateApp(BinaryEmulator Instance, bool Active, bool FromHost)
        {
            List<ulong> TopLevel = Instance.WinHelper.TopLevelWindows;
            for (int i = TopLevel.Count - 1; i >= 0; i--)
                PostNotification(Instance, TopLevel[i], WM_ACTIVATEAPP, Active ? 1UL : 0UL, 0, FromHost);
        }

        internal static void MoveFocus(BinaryEmulator Instance, ulong Focus, bool FromHost)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong Previous = Helper.FocusWindow;
            if (Previous == Focus)
                return;

            Helper.FocusWindow = Focus;

            if (Previous != 0 && Helper.GetWindow(Previous) != null)
                PostNotification(Instance, Previous, WM_KILLFOCUS, Focus, 0, FromHost);

            if (Focus != 0)
                PostNotification(Instance, Focus, WM_SETFOCUS, Previous, 0, FromHost);

            Helper.PublishFocusState(Focus, Helper.ActiveWindow);
        }

        private static readonly (byte Vk, uint Message)[] MouseButtonReleases =
        {
            (VkLButton, WM_LBUTTONUP),
            (VkRButton, WM_RBUTTONUP),
            (VkMButton, WM_MBUTTONUP),
            (VkXButton1, WM_XBUTTONUP),
            (VkXButton1 + 1, WM_XBUTTONUP),
        };

        private static void ReleaseHeldButtons(BinaryEmulator Instance, Win32kState State, ulong Foreground)
        {
            GetClientOrigin(Instance, Instance.WinHelper.GetWindow(Foreground), out int OriginX, out int OriginY);
            ulong Position = WinSysHelper.PackCoordinates(State.CursorScreenX - OriginX, State.CursorScreenY - OriginY);

            for (int i = 0; i < MouseButtonReleases.Length; i++)
            {
                (byte Vk, uint Message) = MouseButtonReleases[i];
                if ((State.KeyState[Vk] & 0x80) == 0)
                    continue;

                SetKeyDown(State, Vk, false);

                ulong WParam = Message == WM_XBUTTONUP ? (ulong)(Vk - VkXButton1 + 1) << 16 : 0;
                ulong LParam = Position;
                if (Win32kRawInput.DeliverHostEvent(Instance, Foreground, Message, WParam, LParam))
                    PostMessage(Instance, ResolveInputTarget(Instance, Foreground, Message, ref LParam), Message, WParam, LParam);
            }
        }

        private static void ReleaseHeldKeys(BinaryEmulator Instance, Win32kState State, ulong Foreground)
        {
            ReleaseHeldButtons(Instance, State, Foreground);

            // A deactivated queue holds nothing down, key up posted or not.
            for (int Vk = 0; Vk < State.KeyState.Length; Vk++)
                State.KeyState[Vk] &= 0x01;

            if (State.KeysHeld == 0)
                return;

            // Repeat count one, previous state down, transition up.
            const ulong ReleaseLParam = 0xC0000001;

            for (int Vk = 0; Vk < State.KeyDownMessage.Length && State.KeysHeld != 0; Vk++)
            {
                if (State.KeyDownMessage[Vk] == 0)
                    continue;

                uint Message = State.KeyDownMessage[Vk] == 2 ? WM_SYSKEYUP : WM_KEYUP;
                State.KeyDownMessage[Vk] = 0;
                State.KeysHeld--;

                ulong LParam = ReleaseLParam;
                if (Win32kRawInput.DeliverHostEvent(Instance, Foreground, Message, (ulong)Vk, LParam))
                    PostMessage(Instance, ResolveInputTarget(Instance, Foreground, Message, ref LParam), Message, (ulong)Vk, LParam);
            }
        }

        // LParam is in the client coordinates of Root.
        private static ulong ResolveInputTarget(BinaryEmulator Instance, ulong Root, uint Message, ref ulong LParam)
        {
            if (Message >= WM_KEYDOWN && Message <= WM_SYSCHAR)
            {
                ulong Focus = Instance.WinHelper.FocusWindow;
                return Focus != 0 && Instance.WinHelper.GetWindow(Focus) != null ? Focus : Root;
            }

            if (Message < WM_MOUSEMOVE || Message > WM_RBUTTONUP)
                return Root;

            int X = (short)(LParam & 0xFFFF);
            int Y = (short)((LParam >> 16) & 0xFFFF);

            ulong Capture = GetCaptureWindow(Instance);
            ulong Target = Capture != 0 && Instance.WinHelper.GetWindow(Capture) != null
                ? Capture
                : ChildFromPoint(Instance, Root, X, Y, 0);

            if (Target == Root)
                return Root;

            GetClientScreenOrigin(Instance, Root, out int RootX, out int RootY);
            GetClientScreenOrigin(Instance, Target, out int TargetX, out int TargetY);
            int ClientX = X + RootX - TargetX;
            int ClientY = Y + RootY - TargetY;
            LParam = WinSysHelper.PackCoordinates(ClientX, ClientY);
            return Target;
        }

        internal static void GetClientScreenOrigin(BinaryEmulator Instance, ulong Hwnd, out int X, out int Y)
        {
            Instance.WinHelper.GetSurfaceOrigin(Hwnd, out int OffsetX, out int OffsetY, out ulong Root);
            GetClientOrigin(Instance, Instance.WinHelper.GetWindow(Root), out X, out Y);
            X += OffsetX;
            Y += OffsetY;
        }

        internal const uint WindowStyleDisabled = 0x08000000;

        // X and Y are client coordinates of the top level window, which is the surface every child sits on.
        private static ulong ChildFromPoint(BinaryEmulator Instance, ulong Hwnd, int X, int Y, int Depth)
        {
            if (Depth >= MaxWindowTreeDepth)
                return Hwnd;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Hwnd;

            for (int i = 0; i < Window.Children.Count; i++)
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

        internal static void DropRawInputMessages(BinaryEmulator Instance, uint LastHandle)
        {
            Win32kState State = GetState(Instance);
            Queue<Win32kMessage> Queue = State.MessageQueue;
            int Count = Queue.Count;
            if (Count == 0)
                return;

            for (int i = 0; i < Count; i++)
            {
                Win32kMessage Message = Queue.Dequeue();
                if (Message.Message == WM_INPUT && (int)(LastHandle - (uint)Message.LParam) >= 0)
                    continue;

                Queue.Enqueue(Message);
            }
        }

        internal static bool HasSentMessageFor(BinaryEmulator Instance, uint ThreadId)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            foreach (ulong Hwnd in State.PendingWindowPosChanged)
            {
                WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
                if (Window != null && Window.PendingWindowPosChanged && Window.WndProc != 0
                    && (Window.OwnerThreadId == 0 || Window.OwnerThreadId == ThreadId))
                {
                    return true;
                }
            }

            return HasIncomingNotification(Instance, State, ThreadId);
        }

        // Owner thread only. The window procedure runs in its frame.
        internal static bool TryDeliverWindowPosChanged(BinaryEmulator Instance, ulong SyscallResult, ulong SyscallRetryRip = 0)
        {
            Queue<ulong> Pending = GetState(Instance).PendingWindowPosChanged;
            uint ThreadId = Instance.CurrentThread?.ThreadId ?? 0;

            for (int Count = Pending.Count; Count > 0; Count--)
            {
                ulong Hwnd = Pending.Dequeue();
                WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
                if (Window == null || !Window.PendingWindowPosChanged)
                    continue;

                if (Window.WndProc == 0)
                {
                    Window.PendingWindowPosChanged = false;
                    continue;
                }

                if (Window.OwnerThreadId != 0 && Window.OwnerThreadId != ThreadId)
                {
                    Pending.Enqueue(Hwnd);
                    continue;
                }

                ulong WindowPos = Instance.WinHelper.EnsureWindowPosStruct(Window, Window.PendingWindowPosFlags);
                if (WindowPos == 0)
                {
                    Window.PendingWindowPosChanged = false;
                    continue;
                }

                if (!Instance.WinHelper.BeginGuestCall(Window.WndProc, Hwnd, WM_WINDOWPOSCHANGED, 0, WindowPos, SyscallResult, SyscallRetryRip))
                {
                    Pending.Enqueue(Hwnd);
                    return false;
                }

                Window.PendingWindowPosChanged = false;
                return true;
            }

            return false;
        }

        private const uint WindowStyleBorder = 0x00800000;
        private const uint WindowStyleDlgFrame = 0x00400000;
        private const uint WindowStyleCaption = WindowStyleBorder | WindowStyleDlgFrame;
        private const uint WindowStyleThickFrame = 0x00040000;
        private const uint WindowExStyleDlgModalFrame = 0x00000001;
        private const uint WindowExStyleToolWindow = 0x00000080;
        private const uint WindowExStyleClientEdge = 0x00000200;
        private const uint WindowExStyleStaticEdge = 0x00020000;

        // AdjustWindowRectExForDpi metrics at 96 DPI.
        private const int FrameSizeBorder = 4;
        private const int FramePaddedBorder = 4;
        private const int FrameFixedBorder = 3;
        private const int FrameEdge = 2;
        private const int FrameCaption = 23;
        private const int FrameSmallCaption = 23;

        // Follows AdjustWindowRectEx. No menu is ever drawn, so a menu bar adds no height.
        internal static void GetFrameInsets(BinaryEmulator Instance, WinWindow Window, out int Left, out int Top, out int Right, out int Bottom)
        {
            uint Style = Window.Style;
            uint ExStyle = Window.ExStyle;
            uint Dpi = Win32kDpi.GetEffectiveDpi(Instance);

            int Border = 0;
            if ((ExStyle & (WindowExStyleStaticEdge | WindowExStyleDlgModalFrame)) == WindowExStyleStaticEdge)
                Border = 1;
            else if ((ExStyle & WindowExStyleDlgModalFrame) != 0 || (Style & (WindowStyleThickFrame | WindowStyleDlgFrame)) != 0)
                Border = 2;

            if ((Style & WindowStyleThickFrame) != 0)
                Border += WinSysHelper.ScaleMetric(FrameSizeBorder, Dpi) + WinSysHelper.ScaleMetric(FramePaddedBorder, Dpi) - WinSysHelper.ScaleMetric(FrameFixedBorder, Dpi);

            if ((Style & (WindowStyleBorder | WindowStyleDlgFrame)) != 0 || (ExStyle & WindowExStyleDlgModalFrame) != 0)
                Border++;

            if ((ExStyle & WindowExStyleClientEdge) != 0)
                Border += WinSysHelper.ScaleMetric(FrameEdge, Dpi);

            Left = Border;
            Top = Border;
            Right = Border;
            Bottom = Border;

            if ((Style & WindowStyleCaption) == WindowStyleCaption)
                Top += WinSysHelper.ScaleMetric((ExStyle & WindowExStyleToolWindow) != 0 ? FrameSmallCaption : FrameCaption, Dpi);
        }

        // Left and Top are in the window rect's space, not the Win32 client origin.
        internal static void GetClientRect(BinaryEmulator Instance, WinWindow Window, out int Left, out int Top, out int Width, out int Height)
        {
            GetFrameInsets(Instance, Window, out int InsetLeft, out int InsetTop, out int InsetRight, out int InsetBottom);

            Left = Window.X + InsetLeft;
            Top = Window.Y + InsetTop;
            Width = Math.Max((int)Window.Width - InsetLeft - InsetRight, 0);
            Height = Math.Max((int)Window.Height - InsetTop - InsetBottom, 0);
        }

        internal static void GetAbsoluteWindowPosition(BinaryEmulator Instance, WinWindow Window, out int Left, out int Top)
        {
            Left = Window.X;
            Top = Window.Y;

            ulong ParentHwnd = Window.ParentHwnd;
            while (ParentHwnd != 0)
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(ParentHwnd);
                if (Parent == null)
                    break;

                GetClientRect(Instance, Parent, out int ClientLeft, out int ClientTop, out _, out _);
                Left += ClientLeft;
                Top += ClientTop;
                ParentHwnd = Parent.ParentHwnd;
            }
        }

        internal static ulong WindowFromPoint(BinaryEmulator Instance, int X, int Y)
        {
            ulong Found = 0;
            List<ulong> TopLevel = Instance.WinHelper.TopLevelWindows;

            for (int i = TopLevel.Count - 1; i >= 0 && Found == 0; i--)
                Found = HitTest(Instance, Instance.WinHelper.GetWindow(TopLevel[i]), X, Y);

            return Found;
        }

        private static ulong HitTest(BinaryEmulator Instance, WinWindow Window, int X, int Y)
        {
            if (Window == null || Window.Destroyed || !Window.Visible || (Window.ExStyle & WindowExStyleTransparent) != 0)
                return 0;

            GetAbsoluteWindowPosition(Instance, Window, out int Left, out int Top);
            if (X < Left || Y < Top || X >= Left + (int)Window.Width || Y >= Top + (int)Window.Height)
                return 0;

            foreach (ulong Child in Window.Children)
            {
                ulong Hit = HitTest(Instance, Instance.WinHelper.GetWindow(Child), X, Y);
                if (Hit != 0)
                    return Hit;
            }

            return Window.Hwnd;
        }

        internal static void GetClientSize(BinaryEmulator Instance, WinWindow Window, out int Width, out int Height)
        {
            GetClientRect(Instance, Window, out _, out _, out Width, out Height);
        }

        internal static void GetClientOrigin(BinaryEmulator Instance, WinWindow Window, out int Left, out int Top)
        {
            if (Window == null)
            {
                Left = 0;
                Top = 0;
                return;
            }

            GetClientRect(Instance, Window, out Left, out Top, out _, out _);
        }

        private static bool ApplyHostMove(BinaryEmulator Instance, ulong Hwnd, ulong LParam)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return false;

            // The host reports its client origin, and the guest frame hangs off that.
            GetFrameInsets(Instance, Window, out int InsetLeft, out int InsetTop, out _, out _);
            int X = (short)(LParam & 0xFFFF) - InsetLeft;
            int Y = (short)((LParam >> 16) & 0xFFFF) - InsetTop;
            if (X == Window.X && Y == Window.Y)
                return false;

            Window.X = X;
            Window.Y = Y;
            Instance.WinHelper.MaterializeUserWindow(Window);

            // The clip is guest screen coordinates, so a move changes the client origin.
            Win32kState State = GetState(Instance);
            if (State.CursorClipped)
                ApplyHostCursorClip(Instance, State);

            return true;
        }

        private static bool ApplyHostResize(BinaryEmulator Instance, ulong Hwnd, ulong WParam, ulong LParam)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return false;

            uint Width = (uint)(LParam & 0xFFFF);
            uint Height = (uint)((LParam >> 16) & 0xFFFF);

            // A frame with no client area is iconic whatever it calls itself. Only the client rectangle
            // collapses, so the size and maximized flag keep the values to restore to.
            bool Minimized = WParam == SIZE_MINIMIZED || Width == 0 || Height == 0;
            bool Maximized = Window.Maximized;
            uint OuterWidth = Window.Width;
            uint OuterHeight = Window.Height;

            if (!Minimized)
            {
                GetFrameInsets(Instance, Window, out int InsetLeft, out int InsetTop, out int InsetRight, out int InsetBottom);

                Maximized = WParam == SIZE_MAXIMIZED;
                OuterWidth = Width + (uint)(InsetLeft + InsetRight);
                OuterHeight = Height + (uint)(InsetTop + InsetBottom);
            }

            if (Minimized == Window.Minimized && Maximized == Window.Maximized && OuterWidth == Window.Width && OuterHeight == Window.Height)
                return false;

            SetShowState(Window, Minimized, Maximized);
            Window.Width = OuterWidth;
            Window.Height = OuterHeight;

            MarkWindowDirty(Instance, Window);
            Instance.WinHelper.MaterializeUserWindow(Window);
            return true;
        }

        // user32 answers IsIconic and IsZoomed from the style bits.
        internal static void SetShowState(WinWindow Window, bool Minimized, bool Maximized)
        {
            const uint WS_MINIMIZE = 0x20000000;
            const uint WS_MAXIMIZE = 0x01000000;

            Window.Minimized = Minimized;
            Window.Maximized = Maximized;
            Window.Style = (Window.Style & ~(WS_MINIMIZE | WS_MAXIMIZE))
                | (Minimized ? WS_MINIMIZE : 0)
                | (Maximized && !Minimized ? WS_MAXIMIZE : 0);
        }

        internal static void SetExStyle(WinWindow Window, uint ExStyle)
        {
            if ((ExStyle & WindowExStyleLayered) == 0)
            {
                Window.LayeredByAttributes = false;
                Window.LayeredByUpdate = false;
            }

            Window.ExStyle = ExStyle;
        }

        /// <summary>
        /// Screen position of the pointer, tracked from the client-relative coordinates the host window manager
        /// reports for the foreground window.
        /// </summary>
        internal static void GetCursorPosition(BinaryEmulator Instance, out int X, out int Y)
        {
            DrainHostEvents(Instance);

            // NT: one system cursor, which also moves over other programs.
            Win32kState State = GetState(Instance);
            if (Win32kDpi.TryGetHostCursorPosition(Instance, out int HostX, out int HostY))
            {
                State.CursorScreenX = HostX;
                State.CursorScreenY = HostY;
            }

            X = State.CursorScreenX;
            Y = State.CursorScreenY;
        }

        internal static void SetCursorClip(BinaryEmulator Instance, int Left, int Top, int Right, int Bottom)
        {
            Win32kState State = GetState(Instance);
            State.CursorClipped = true;
            State.ClipLeft = Math.Min(Left, Right);
            State.ClipTop = Math.Min(Top, Bottom);
            State.ClipRight = Math.Max(Left, Right);
            State.ClipBottom = Math.Max(Top, Bottom);
            ApplyHostCursorClip(Instance, State);
        }

        internal static void ClearCursorClip(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            State.CursorClipped = false;
            ApplyHostCursorClip(Instance, State);
        }

        // A pointer that has left the window reports no motion, so the host has to hold the clip.
        private static void ApplyHostCursorClip(BinaryEmulator Instance, Win32kState State)
        {
            WinWindow Foreground = Instance.WinHelper.GetWindow(Instance.WinHelper.GetForegroundWindow())
                ?? Instance.WinHelper.GetWindow(Instance.WinHelper.GetTopVisibleWindow());
            ulong Hwnd = Foreground?.Hwnd ?? 0;

            if (!State.CursorClipped)
            {
                Instance.WinHelper.SetHostCursorClip(Hwnd, false, 0, 0, 0, 0);
                return;
            }

            GetClientOrigin(Instance, Foreground, out int OriginX, out int OriginY);

            Instance.WinHelper.SetHostCursorClip(Hwnd, true,
                State.ClipLeft - OriginX,
                State.ClipTop - OriginY,
                State.ClipRight - OriginX,
                State.ClipBottom - OriginY);
        }

        internal static bool TryGetCursorClip(BinaryEmulator Instance, out int Left, out int Top, out int Right, out int Bottom)
        {
            Win32kState State = GetState(Instance);
            Left = State.ClipLeft;
            Top = State.ClipTop;
            Right = State.ClipRight;
            Bottom = State.ClipBottom;
            return State.CursorClipped;
        }

        internal static void SetCursorPosition(BinaryEmulator Instance, int X, int Y)
        {
            DrainHostEvents(Instance);

            WinWindow Foreground = Instance.WinHelper.GetWindow(Instance.WinHelper.GetForegroundWindow())
                ?? Instance.WinHelper.GetWindow(Instance.WinHelper.GetTopVisibleWindow());
            GetClientOrigin(Instance, Foreground, out int OriginX, out int OriginY);
            int ClientX = X - OriginX;
            int ClientY = Y - OriginY;

            Win32kState State = GetState(Instance);
            State.CursorScreenX = X;
            State.CursorScreenY = Y;

            Instance.WinHelper.WarpHostCursor(Foreground?.Hwnd ?? 0, ClientX, ClientY);
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

        internal static void SetCursorIconData(BinaryEmulator Instance, ulong Handle, Win32kCursorIcon Data)
        {
            GetState(Instance).CursorIcons[Handle] = Data;
        }

        internal static bool TryGetCursorIcon(BinaryEmulator Instance, ulong Handle, out Win32kCursorIcon Data)
        {
            return GetState(Instance).CursorIcons.TryGetValue(Handle, out Data);
        }

        internal static bool DestroyCursorIcon(BinaryEmulator Instance, ulong Handle)
        {
            Win32kState State = GetState(Instance);
            if (!State.CursorIcons.Remove(Handle))
                return false;

            if (Handle != State.StockCursor && Handle != State.CursorHandle)
                Instance.WinHelper.ReleaseUserHandle(Handle);

            return true;
        }

        internal static ulong GetCursorHandle(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            return State.CursorAssigned ? State.CursorHandle : EnsureStockCursor(Instance);
        }

        internal static bool IsCursorShowing(BinaryEmulator Instance)
        {
            Win32kState State = GetState(Instance);
            return State.CursorShowCount >= 0 && !State.CursorHiddenWhileTyping;
        }

        internal static bool LockWindowUpdate(BinaryEmulator Instance, ulong Hwnd)
        {
            Win32kState State = GetState(Instance);

            if (Hwnd == 0)
            {
                ulong Locked = State.UpdateLockWindow;
                State.UpdateLockWindow = 0;

                WinWindow Window = Locked != 0 ? Instance.WinHelper.GetWindow(Locked) : null;
                if (Window != null && Window.Visible)
                    MarkWindowDirty(Instance, Window);

                return true;
            }

            if (State.UpdateLockWindow != 0 && State.UpdateLockWindow != Hwnd)
                return false;

            if (Instance.WinHelper.GetWindow(Hwnd) == null)
                return false;

            State.UpdateLockWindow = Hwnd;
            return true;
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

        // WM_PAINT is not queued. The message fetch reports one while the flag stands.
        internal static void MarkWindowDirty(BinaryEmulator Instance, WinWindow Window)
        {
            if (Window == null || Window.Destroyed)
                return;

            GetScreenRects(Instance, Window, out _, out GdiClipRect Client);
            AddUpdateRegion(Instance, Window, null, Client);
        }

        internal const uint RDW_INVALIDATE = 0x0001;
        internal const uint RDW_ERASE = 0x0004;
        internal const uint RDW_VALIDATE = 0x0008;
        internal const uint RDW_NOERASE = 0x0020;
        internal const uint RDW_NOCHILDREN = 0x0040;
        internal const uint RDW_ALLCHILDREN = 0x0080;
        internal const uint RDW_UPDATENOW = 0x0100;
        internal const uint RDW_FRAME = 0x0400;

        // NT: NtUserRedrawWindow refuses these.
        internal const uint RDW_RESERVED = 0xFFFFF000;

        // NT: InternalInvalidate2 sets this on flags passed to a child.
        private const uint RdwChild = 0x2000;

        // NT: lets an invalidation reach layered children.
        private const uint RdwReachLayered = 0x10000;

        // NT: zzzBltValidBits flags.
        private const uint RdwUncovered = RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN;
        private const uint RdwWholeWindow = RdwUncovered | RDW_FRAME;

        private const uint WindowStyleClipSiblings = 0x04000000;
        private const uint WindowStyleClipChildren = 0x02000000;
        internal const uint WindowExStyleTransparent = 0x00000020;
        internal const uint WindowExStyleLayered = 0x00080000;
        private const uint WindowExStyleComposited = 0x02000000;

        private const int MaxUpdateRects = 32;

        internal static bool InvalidateWindow(BinaryEmulator Instance, ulong Hwnd)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || Window.Destroyed)
                return false;

            RedrawWindow(Instance, Window, null, RDW_INVALIDATE);
            return true;
        }

        internal static List<GdiClipRect> GetRedrawArea(BinaryEmulator Instance)
        {
            List<GdiClipRect> Area = GetState(Instance).RedrawArea;
            Area.Clear();
            return Area;
        }

        // NT: xxxRedrawWindow. Area is in client coordinates, null for the whole window.
        internal static void RedrawWindow(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Area, uint Flags)
        {
            if (Window == null)
            {
                RedrawDesktop(Instance, Area, Flags);
                return;
            }

            if ((Flags & (RDW_INVALIDATE | RDW_VALIDATE)) == 0 || !IsWindowShown(Instance, Window))
                return;

            List<GdiClipRect> ScreenArea = null;
            if (Area != null)
            {
                GetScreenRects(Instance, Window, out _, out GdiClipRect Client);
                ScreenArea = GetState(Instance).InvalidateArea;
                ScreenArea.Clear();
                foreach (GdiClipRect Rect in Area)
                {
                    GdiClipRect Shifted = ShiftRect(Rect, Client.Left, Client.Top);
                    if (!IsEmpty(Shifted))
                        ScreenArea.Add(Shifted);
                }
            }

            InternalInvalidate(Instance, Window, ScreenArea, Flags);
            if ((Flags & RDW_INVALIDATE) != 0)
                Instance.WinHelper.PresentInvalidation();
        }

        // NT: only RDW_ALLCHILDREN reaches the top-level windows, layered ones included. Screen coordinates.
        private static void RedrawDesktop(BinaryEmulator Instance, List<GdiClipRect> Area, uint Flags)
        {
            if ((Flags & (RDW_INVALIDATE | RDW_VALIDATE)) == 0 || (Flags & RDW_ALLCHILDREN) == 0)
                return;

            uint ChildFlags = Flags | RdwChild | RdwReachLayered;
            if ((Flags & RDW_INVALIDATE) != 0)
                ChildFlags |= RDW_ERASE | RDW_FRAME;

            Win32kState State = GetState(Instance);
            List<GdiClipRect> Subtract = Area ?? State.InvalidateSubtract;
            GdiClipRect Screen = new GdiClipRect { Left = int.MinValue, Top = int.MinValue, Right = int.MaxValue, Bottom = int.MaxValue };
            if (Area == null)
            {
                Subtract.Clear();
                Subtract.Add(Screen);
            }

            GdiClipRect[] Whole = Subtract.ToArray();
            List<ulong> TopLevel = Instance.WinHelper.TopLevelWindows;
            for (int i = TopLevel.Count - 1; i >= 0; i--)
            {
                WinWindow Window = Instance.WinHelper.GetWindow(TopLevel[i]);
                if (Window == null || Window.Destroyed || !Window.Visible)
                    continue;

                GetScreenRects(Instance, Window, out GdiClipRect WindowRect, out GdiClipRect ClientRect);
                InvalidateTree(Instance, Window, Area, Subtract, Screen, WindowRect, ClientRect, ChildFlags, 1);
                Subtract.Clear();
                Subtract.AddRange(Whole);
            }

            if ((Flags & RDW_INVALIDATE) != 0)
                Instance.WinHelper.PresentInvalidation();
        }

        internal static bool IsWindowShown(BinaryEmulator Instance, WinWindow Window)
        {
            if (Window == null || Window.Destroyed || !Window.Visible)
                return false;

            for (int Depth = 0; Window.ParentHwnd != 0 && Depth < MaxWindowTreeDepth; Depth++)
            {
                Window = Instance.WinHelper.GetWindow(Window.ParentHwnd);
                if (Window == null)
                    return true;

                if (!Window.Visible || Window.Minimized)
                    return false;
            }

            return true;
        }

        internal static void InvalidateWholeWindow(BinaryEmulator Instance, WinWindow Window)
        {
            if (Window != null && !Window.Destroyed && Window.Visible)
                InternalInvalidate(Instance, Window, null, RdwWholeWindow);
        }

        // NT: xxxInternalInvalidate. Area is in screen coordinates, null for the whole window.
        private static void InternalInvalidate(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Area, uint Flags)
        {
            Win32kState State = GetState(Instance);
            bool Invalidate = (Flags & RDW_INVALIDATE) != 0;

            WinWindow Composited = Invalidate ? FindCompositedAncestor(Instance, Window) : null;
            if (Composited != null)
            {
                // NT: the whole window here, with or without RDW_FRAME.
                if (Area == null)
                {
                    GetScreenRects(Instance, Window, out GdiClipRect Whole, out _);
                    Area = State.InvalidateArea;
                    Area.Clear();
                    Area.Add(Whole);
                }

                Flags |= RDW_ALLCHILDREN;
                Window = Composited;
            }

            GetScreenRects(Instance, Window, out GdiClipRect WindowRect, out GdiClipRect ClientRect);
            GdiClipRect Bound = (Flags & RDW_FRAME) != 0 ? WindowRect : ClientRect;

            List<GdiClipRect> Subtract = Area;
            if (Area == null)
            {
                Subtract = State.InvalidateSubtract;
                Subtract.Clear();
                if (!IsEmpty(Bound))
                    Subtract.Add(Bound);
            }

            if (Invalidate && (IsEmpty(Bound) || !IntersectWithParents(Instance, Window, ref Bound)))
                return;

            InvalidateTree(Instance, Window, Area, Subtract, Bound, WindowRect, ClientRect, Flags, 0);
        }

        private static WinWindow FindCompositedAncestor(BinaryEmulator Instance, WinWindow Window)
        {
            for (int Depth = 0; Window != null && Depth < MaxWindowTreeDepth; Depth++)
            {
                if ((Window.ExStyle & WindowExStyleComposited) != 0)
                    return Window;

                Window = Window.ParentHwnd != 0 ? Instance.WinHelper.GetWindow(Window.ParentHwnd) : null;
            }

            return null;
        }

        // NT: InternalInvalidate2. False once a child that clips its siblings has used up the area.
        private static bool InvalidateTree(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Area, List<GdiClipRect> Subtract,
            in GdiClipRect Parents, in GdiClipRect WindowRect, in GdiClipRect ClientRect, uint Flags, int Depth)
        {
            if (Depth >= MaxWindowTreeDepth)
                return true;

            bool Invalidate = (Flags & RDW_INVALIDATE) != 0;
            GdiClipRect Share = WindowRect;
            if (Invalidate)
            {
                if ((Window.ExStyle & WindowExStyleLayered) == 0)
                    Share = Intersect(WindowRect, Parents);

                if (IsEmpty(Share))
                    return true;

                if (Area != null)
                {
                    ulong Covered = GetCoveredArea(Area, Share);
                    if (Covered == 0)
                        return true;

                    // NT: an area that covers all the window shows is the whole window.
                    if (Covered == GetRectArea(Share))
                        Area = null;
                }
            }

            bool ClipChildren = (Window.Style & WindowStyleClipChildren) != 0;
            if (!ClipChildren)
                ApplyUpdate(Instance, Window, Area, ClientRect, Flags);

            if (Window.Children.Count != 0 && (Flags & RDW_NOCHILDREN) == 0 && !Window.Minimized
                && ((Flags & RDW_ALLCHILDREN) != 0 || !ClipChildren))
            {
                // NT: a child an invalidation reaches is always owed WM_NCPAINT and WM_ERASEBKGND.
                uint ChildFlags = Flags | RdwChild;
                if (Invalidate)
                    ChildFlags |= RDW_ERASE | RDW_FRAME;

                GdiClipRect ChildParents = Intersect(Share, ClientRect);
                int ChildCount = IsEmpty(ChildParents) ? 0 : Window.Children.Count;
                for (int i = 0; i < ChildCount; i++)
                {
                    WinWindow Child = Instance.WinHelper.GetWindow(Window.Children[i]);
                    if (Child == null || Child.Destroyed || !Child.Visible)
                        continue;

                    // NT: skips a layered child, and a layered child takes no share from its siblings and parent.
                    bool Layered = (Child.ExStyle & WindowExStyleLayered) != 0;
                    if (Layered && Invalidate && (Flags & RdwReachLayered) == 0)
                        continue;

                    GetScreenRects(Instance, Child, SaturatingAdd(ClientRect.Left, Child.X), SaturatingAdd(ClientRect.Top, Child.Y),
                        out GdiClipRect ChildWindow, out GdiClipRect ChildClient);

                    GdiClipRect[] Saved = Layered ? Subtract.ToArray() : null;
                    bool Remaining = InvalidateTree(Instance, Child, Area, Subtract, ChildParents, ChildWindow, ChildClient, ChildFlags, Depth + 1);
                    if (Saved != null)
                    {
                        Subtract.Clear();
                        Subtract.AddRange(Saved);
                    }
                    else if (!Remaining)
                    {
                        return false;
                    }
                }
            }

            if (ClipChildren)
                ApplyUpdate(Instance, Window, Area, ClientRect, Flags);

            if ((Flags & RdwChild) == 0 || (Window.ExStyle & (WindowExStyleTransparent | WindowExStyleLayered)) != 0
                || (Window.Style & WindowStyleClipSiblings) == 0)
            {
                return true;
            }

            if ((Flags & RDW_VALIDATE) == 0)
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(Window.ParentHwnd);
                if (Parent == null || (Parent.Style & WindowStyleClipChildren) == 0)
                    return true;
            }

            SubtractRect(Subtract, Share);
            return Subtract.Count != 0;
        }

        // Area holds disjoint rectangles.
        private static ulong GetCoveredArea(List<GdiClipRect> Area, in GdiClipRect Rect)
        {
            ulong Covered = 0;
            foreach (GdiClipRect Part in Area)
            {
                GdiClipRect Overlap = Intersect(Part, Rect);
                if (!IsEmpty(Overlap))
                    Covered += GetRectArea(Overlap);
            }

            return Covered;
        }

        private static ulong GetRectArea(in GdiClipRect Rect)
        {
            return (ulong)((long)Rect.Right - Rect.Left) * (ulong)((long)Rect.Bottom - Rect.Top);
        }

        // NT: InternalInvalidate3. The update region is in client coordinates and not cut to the window.
        private static void ApplyUpdate(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Area, in GdiClipRect ClientRect, uint Flags)
        {
            if ((Flags & RDW_INVALIDATE) != 0)
            {
                // NT: once another thread has invalidated the window, validation waits for the next BeginPaint.
                if (!IsOwnedByCurrentThread(Instance, Window))
                    Window.UpdateDirty = true;

                if ((Flags & RDW_ERASE) != 0)
                    Window.SendEraseBackground = true;

                AddUpdateRegion(Instance, Window, Area, ClientRect);
                return;
            }

            if ((Flags & RDW_VALIDATE) == 0 || Window.UpdateDirty)
                return;

            if ((Flags & RDW_NOERASE) != 0)
                Window.SendEraseBackground = false;

            if (!Window.PaintPending)
                return;

            if (Area != null)
            {
                foreach (GdiClipRect Rect in Area)
                    SubtractRect(Window.UpdateRegion, ShiftRect(Rect, -(long)ClientRect.Left, -(long)ClientRect.Top));
            }

            if (Area == null || Window.UpdateRegion.Count == 0)
            {
                Window.SendEraseBackground = false;
                ClearUpdateArea(Instance, Window);
            }
        }

        private static void AddUpdateRegion(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Area, in GdiClipRect ClientRect)
        {
            List<GdiClipRect> Region = Window.UpdateRegion ??= new List<GdiClipRect>();
            bool WasPending = Region.Count > 0;

            if (Area == null)
            {
                GdiClipRect Client = ToClientRect(ClientRect);
                Region.Clear();
                if (!IsEmpty(Client))
                    Region.Add(Client);
            }
            else
            {
                foreach (GdiClipRect Rect in Area)
                    UnionRect(Instance, Region, ShiftRect(Rect, -(long)ClientRect.Left, -(long)ClientRect.Top));
            }

            if (Region.Count == 0)
            {
                if (WasPending)
                    ClearUpdateArea(Instance, Window);

                return;
            }

            Window.Dirty = true;
            Instance.WinHelper.PublishWindowPaintState(Window);
            Instance.WakeSignal.Bump();
        }

        private static void UnionRect(BinaryEmulator Instance, List<GdiClipRect> Region, in GdiClipRect Rect)
        {
            if (IsEmpty(Rect))
                return;

            List<GdiClipRect> Pieces = GetState(Instance).UnionPieces;
            Pieces.Clear();
            Pieces.Add(Rect);
            for (int i = 0; i < Region.Count && Pieces.Count != 0; i++)
                SubtractRect(Pieces, Region[i]);

            Region.AddRange(Pieces);
            if (Region.Count > MaxUpdateRects)
            {
                GetRegionBounds(Region, out GdiClipRect Bounds);
                Region.Clear();
                Region.Add(Bounds);
            }
        }

        private static void SubtractRect(List<GdiClipRect> Rects, in GdiClipRect Cut)
        {
            if (IsEmpty(Cut))
                return;

            int Width = (int)Math.Min((long)Cut.Right - Cut.Left, int.MaxValue);
            int Height = (int)Math.Min((long)Cut.Bottom - Cut.Top, int.MaxValue);
            WinSysHelper.SubtractClip(Rects, Cut.Right - Width, Cut.Bottom - Height, Width, Height);
        }

        internal static void ClearUpdateArea(BinaryEmulator Instance, WinWindow Window)
        {
            Window.UpdateRegion?.Clear();
            Window.Dirty = false;
            Instance.WinHelper.PublishWindowPaintState(Window);
        }

        // NT: ClrFTrueVis.
        internal static void ClearUpdateTree(BinaryEmulator Instance, WinWindow Window)
        {
            ClearUpdateTree(Instance, Window, 0);
        }

        private static void ClearUpdateTree(BinaryEmulator Instance, WinWindow Window, int Depth)
        {
            if (Depth >= MaxWindowTreeDepth)
                return;

            ClearUpdateArea(Instance, Window);
            for (int i = 0; i < Window.Children.Count; i++)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(Window.Children[i]);
                if (Child != null && Child.Visible)
                    ClearUpdateTree(Instance, Child, Depth + 1);
            }
        }

        // NT: xxxMinMaximizeEx.
        internal static void ClearChildUpdateTrees(BinaryEmulator Instance, WinWindow Window)
        {
            for (int i = 0; i < Window.Children.Count; i++)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(Window.Children[i]);
                if (Child != null)
                    ClearUpdateTree(Instance, Child, 1);
            }
        }

        // No update region means the whole client area.
        internal static void GetUpdateRegion(BinaryEmulator Instance, WinWindow Window, List<GdiClipRect> Rects)
        {
            Rects.Clear();
            GetClientSize(Instance, Window, out int Width, out int Height);
            GdiClipRect Client = new GdiClipRect { Right = Width, Bottom = Height };

            if (!Window.PaintPending)
            {
                if (!IsEmpty(Client))
                    Rects.Add(Client);

                return;
            }

            foreach (GdiClipRect Rect in Window.UpdateRegion)
            {
                GdiClipRect Part = Intersect(Rect, Client);
                if (!IsEmpty(Part))
                    Rects.Add(Part);
            }
        }

        // NT: xxxGetUpdateRect. True while there is an update region, even when the rectangle is empty.
        internal static bool GetUpdateRect(BinaryEmulator Instance, WinWindow Window, out GdiClipRect Rect)
        {
            Rect = default;
            Window.UpdateDirty = false;
            if (!Window.PaintPending)
                return false;

            GetScreenRects(Instance, Window, out _, out GdiClipRect ClientRect);
            GetRegionBounds(Window.UpdateRegion, out GdiClipRect Bounds);
            GdiClipRect Shown = Intersect(ShiftRect(Bounds, ClientRect.Left, ClientRect.Top), ClientRect);
            if (!IsEmpty(Shown) && IntersectWithParents(Instance, Window, ref Shown))
                Rect = ShiftRect(Shown, -(long)ClientRect.Left, -(long)ClientRect.Top);

            return true;
        }

        // NT: IntersectWithParents.
        private static bool IntersectWithParents(BinaryEmulator Instance, WinWindow Window, ref GdiClipRect Rect)
        {
            for (int Depth = 0; Window.ParentHwnd != 0 && Depth < MaxWindowTreeDepth; Depth++)
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(Window.ParentHwnd);
                if (Parent == null)
                    break;

                if (!Parent.Visible || Parent.Minimized)
                    return false;

                GetScreenRects(Instance, Parent, out _, out GdiClipRect ParentClient);
                Rect = Intersect(Rect, ParentClient);
                if (IsEmpty(Rect))
                    return false;

                Window = Parent;
            }

            return true;
        }

        private const uint SwScrollChildren = 0x0001;
        private const uint SwInvalidate = 0x0002;
        private const uint SwErase = 0x0004;

        // NT: xxxScrollWindowEx. Scroll and Clip are in client coordinates.
        internal static int ScrollWindow(BinaryEmulator Instance, WinWindow Window, int Dx, int Dy, GdiClipRect? Scroll, GdiClipRect? Clip,
            ulong Region, bool WantsRect, uint Flags, out GdiClipRect UpdateRect, out WinScrollChildMoves Moves)
        {
            Win32kState State = GetState(Instance);
            bool ScrollChildren = (Flags & SwScrollChildren) != 0;
            UpdateRect = default;
            Moves = null;

            if ((Dx | Dy) == 0 || !IsWindowShown(Instance, Window))
            {
                if (Region != 0)
                {
                    State.ScrollExposed.Clear();
                    WriteRegion(Instance, Region, State.ScrollExposed);
                }

                // NT: a hidden window still moves its children when no scroll rectangle limits them.
                if ((Dx | Dy) != 0 && ScrollChildren && !Window.Minimized && Scroll == null)
                    Moves = MoveScrolledChildren(Instance, Window, Dx, Dy, null);

                return RegionNull;
            }

            GetClientSize(Instance, Window, out int Width, out int Height);
            GdiClipRect Client = new GdiClipRect { Right = Width, Bottom = Height };

            // NT: with SW_SCROLLCHILDREN the DC does not clip the children.
            List<GdiClipRect> Visible = State.ScrollClip;
            Visible.Clear();
            if (!Window.Minimized && !IsEmpty(Client))
            {
                GdiClipRect[] WindowClip = ScrollChildren
                    ? Instance.WinHelper.GetWindowClipWithChildren(Window.Hwnd)
                    : Instance.WinHelper.GetWindowClip(Window.Hwnd);
                AddClientVisibleArea(Instance, Window.Hwnd, WindowClip, Client, Visible);
            }

            // NT keeps an update region that covers the client area as HRGN_FULL.
            List<GdiClipRect> Update = Window.PaintPending ? Window.UpdateRegion : null;
            bool UpdateWhole = Update != null && !IsEmpty(Client) && GetCoveredArea(Update, Client) == GetRectArea(Client);

            bool WantsExposed = Region != 0 || WantsRect || (Flags & SwInvalidate) != 0;
            int Result = ScrollArea(Instance, Visible, Scroll ?? Client, Clip, Dx, Dy, UpdateWhole ? null : Update, UpdateWhole,
                Region, WantsExposed, 0, 0, out UpdateRect);

            if (State.ScrollValid.Count != 0)
                Instance.WinHelper.EnqueueGdiCopy(Window.Hwnd, State.ScrollValid, Dx, Dy);

            if (ScrollChildren)
            {
                Win32kCaret Caret = GetOwnedCaret(Instance, Window.Hwnd);
                if (Caret != null)
                {
                    GdiClipRect CaretRect = new GdiClipRect
                    {
                        Left = Caret.X,
                        Top = Caret.Y,
                        Right = SaturatingAdd(Caret.X, Caret.Width),
                        Bottom = SaturatingAdd(Caret.Y, Caret.Height),
                    };

                    if (Scroll == null || !IsEmpty(Intersect(CaretRect, Scroll.Value)))
                    {
                        Caret.X = unchecked(Caret.X + Dx);
                        Caret.Y = unchecked(Caret.Y + Dy);
                    }
                }

                Moves = MoveScrolledChildren(Instance, Window, Dx, Dy, Scroll);
            }

            if (Result != RegionError && (Flags & SwInvalidate) != 0)
                RedrawWindow(Instance, Window, State.ScrollExposed, RDW_INVALIDATE | RDW_ALLCHILDREN | ((Flags & SwErase) != 0 ? RDW_ERASE : 0));

            return Result;
        }

        // NT: _ScrollDC. Scroll and Clip are logical. The region comes back in device coordinates, UpdateRect logical.
        internal static int ScrollDc(BinaryEmulator Instance, ulong Hdc, int Dx, int Dy, GdiClipRect? Scroll, GdiClipRect? Clip, ulong Region,
            bool WantsRect, out GdiClipRect UpdateRect)
        {
            UpdateRect = default;
            Win32kState State = GetState(Instance);
            if (!State.DeviceContexts.TryGetValue(Hdc, out Win32kDeviceContext Dc))
                return RegionError;

            List<GdiClipRect> Visible = State.ScrollClip;
            GetDcEffectiveArea(Instance, Dc, Visible);
            GetRegionBounds(Visible, out GdiClipRect ClipBox);
            Instance.WinHelper.ReadDcOrigin(Hdc, out int OffsetX, out int OffsetY);

            GdiClipRect Source = Scroll != null ? ShiftRect(Scroll.Value, OffsetX, OffsetY) : ClipBox;
            GdiClipRect? DeviceClip = Clip != null ? ShiftRect(Clip.Value, OffsetX, OffsetY) : null;

            // NT: FastWindowFromDC finds no window for a DC on the composed desktop, so no update region is left out.
            int Result = ScrollArea(Instance, Visible, Source, DeviceClip, Dx, Dy, null, false, Region, Region != 0 || WantsRect,
                OffsetX, OffsetY, out UpdateRect);

            if (State.ScrollValid.Count != 0 && (Dx | Dy) != 0)
                MoveDcBits(Instance, Dc, Hdc, State.ScrollValid, Dx, Dy);

            return Result;
        }

        // NT: InternalScrollDC. Device coordinates. Fills ScrollValid and ScrollExposed.
        private static int ScrollArea(BinaryEmulator Instance, List<GdiClipRect> Visible, in GdiClipRect Source, GdiClipRect? Clip,
            int Dx, int Dy, List<GdiClipRect> Update, bool UpdateWhole, ulong Region, bool WantsExposed, int OffsetX, int OffsetY,
            out GdiClipRect UpdateRect)
        {
            Win32kState State = GetState(Instance);
            List<GdiClipRect> Valid = State.ScrollValid;
            List<GdiClipRect> Exposed = State.ScrollExposed;
            Valid.Clear();
            Exposed.Clear();
            UpdateRect = default;

            if (Clip != null)
                WinSysHelper.IntersectClip(Visible, Clip.Value);

            if (Visible.Count == 0)
                return Region != 0 && WriteRegion(Instance, Region, Exposed) == RegionError ? RegionError : RegionNull;

            GetRegionBounds(Visible, out GdiClipRect ClipBox);
            bool ClipSimple = GetCoveredArea(Visible, ClipBox) == GetRectArea(ClipBox);
            GdiClipRect Target = ShiftRect(Source, Dx, Dy);

            bool Direct = false;
            bool SourceOnly = false;
            GdiClipRect SourceBox = Intersect(Source, ClipBox);
            if (ClipSimple && Update == null)
            {
                GdiClipRect Overlap = Intersect(SourceBox, Intersect(Target, ClipBox));
                if (IsEmpty(SourceBox))
                    Direct = true;
                else if (!IsEmpty(Overlap))
                    Direct = Dx == 0 || Dy == 0;
                else
                    Direct = SourceOnly = SourceBox.Left == Source.Left && SourceBox.Top == Source.Top
                        && SourceBox.Right == Source.Right && SourceBox.Bottom == Source.Bottom;
            }

            List<GdiClipRect> SourceArea = State.ScrollSource;
            SourceArea.Clear();
            SourceArea.AddRange(Visible);
            WinSysHelper.IntersectClip(SourceArea, Source);

            List<GdiClipRect> TargetArea = State.ScrollTarget;
            TargetArea.Clear();
            TargetArea.AddRange(Visible);
            WinSysHelper.IntersectClip(TargetArea, Target);

            // NT: the update region does not move.
            List<GdiClipRect> Work = State.ScrollWork;
            if (!UpdateWhole)
            {
                Work.Clear();
                foreach (GdiClipRect Rect in SourceArea)
                    Work.Add(ShiftRect(Rect, Dx, Dy));

                CombineRegions(Work, TargetArea, RgnAnd, Valid);
                if (Update != null)
                {
                    foreach (GdiClipRect Rect in Update)
                    {
                        SubtractRect(Valid, Rect);
                        SubtractRect(Valid, ShiftRect(Rect, Dx, Dy));
                    }
                }
            }

            if (SourceOnly)
            {
                Exposed.Add(SourceBox);
            }
            else
            {
                CombineRegions(SourceArea, TargetArea, RgnOr, Work);
                CombineRegions(Work, Valid, RgnDiff, Exposed);
            }

            GetRegionBounds(Exposed, out GdiClipRect ExposedBox);
            if (Exposed.Count > 1 && GetCoveredArea(Exposed, ExposedBox) == GetRectArea(ExposedBox))
            {
                Exposed.Clear();
                Exposed.Add(ExposedBox);
            }

            if (!Direct && !WantsExposed)
                return ClipSimple ? RegionSimple : RegionComplex;

            // NT: a direct rectangle reaches prcUpdate even when hrgnUpdate cannot take it.
            if (Direct)
                UpdateRect = ExposedBox;

            if (Region != 0 && WriteRegion(Instance, Region, Exposed) == RegionError)
            {
                Valid.Clear();
                Exposed.Clear();
                return RegionError;
            }

            UpdateRect = ShiftRect(ExposedBox, -(long)OffsetX, -(long)OffsetY);
            return GetRegionType(Exposed);
        }

        // NT: OffsetChildren. Scroll is in client coordinates.
        private static WinScrollChildMoves MoveScrolledChildren(BinaryEmulator Instance, WinWindow Window, int Dx, int Dy, GdiClipRect? Scroll)
        {
            GetScreenRects(Instance, Window, out _, out GdiClipRect Client);
            GdiClipRect? ScreenScroll = Scroll != null ? ShiftRect(Scroll.Value, Client.Left, Client.Top) : null;
            OffsetChildren(Instance, Window, Client.Left, Client.Top, false, Dx, Dy, ScreenScroll, 0);

            // NT: the test offsets the scroll rectangle by the parent's client origin, none for a top-level window.
            GdiClipRect? Moved = null;
            if (Scroll != null)
            {
                long OriginX = 0;
                long OriginY = 0;
                WinWindow Parent = Window.ParentHwnd != 0 ? Instance.WinHelper.GetWindow(Window.ParentHwnd) : null;
                if (Parent != null)
                {
                    GetScreenRects(Instance, Parent, out _, out GdiClipRect ParentClient);
                    OriginX = ParentClient.Left;
                    OriginY = ParentClient.Top;
                }

                Moved = ShiftRect(Scroll.Value, OriginX + Dx, OriginY + Dy);
            }

            WinScrollChildMoves Moves = null;
            foreach (ulong ChildHwnd in Window.Children)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(ChildHwnd);
                if (Child == null || Child.Destroyed)
                    continue;

                if (Moved != null)
                {
                    GetScreenRects(Instance, Child, out GdiClipRect ChildRect, out _);
                    if (IsEmpty(Intersect(ChildRect, Moved.Value)))
                        continue;
                }

                Moves ??= new WinScrollChildMoves();
                Moves.Children.Add(ChildHwnd);
            }

            return Moves;
        }

        // NT: OffsetChildren. A child the scroll rectangle misses keeps its screen position, with its subtree.
        // ParentX and ParentY are the parent's screen client origin before the move.
        private static void OffsetChildren(BinaryEmulator Instance, WinWindow Parent, int ParentX, int ParentY, bool ParentMoved,
            int Dx, int Dy, GdiClipRect? Scroll, int Depth)
        {
            if (Depth >= MaxWindowTreeDepth)
                return;

            foreach (ulong ChildHwnd in Parent.Children)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(ChildHwnd);
                if (Child == null || Child.Destroyed)
                    continue;

                GetScreenRects(Instance, Child, SaturatingAdd(ParentX, Child.X), SaturatingAdd(ParentY, Child.Y),
                    out GdiClipRect WindowRect, out GdiClipRect ClientRect);

                bool Moves = Scroll == null || !IsEmpty(Intersect(WindowRect, Scroll.Value));
                if (Moves != ParentMoved)
                {
                    Child.X = Moves ? unchecked(Child.X + Dx) : unchecked(Child.X - Dx);
                    Child.Y = Moves ? unchecked(Child.Y + Dy) : unchecked(Child.Y - Dy);
                    Instance.WinHelper.MaterializeUserWindow(Child);
                }

                if (Moves)
                    OffsetChildren(Instance, Child, ClientRect.Left, ClientRect.Top, true, Dx, Dy, Scroll, Depth + 1);
            }
        }

        // NT: WM_MOVE to each child after the scroll. True while a window procedure runs.
        internal static bool SendScrollChildMoves(BinaryEmulator Instance, WinScrollChildMoves Moves)
        {
            while (Moves.Next < Moves.Children.Count)
            {
                WinWindow Child = Instance.WinHelper.GetWindow(Moves.Children[Moves.Next++]);
                if (Child == null || Child.Destroyed)
                    continue;

                GetClientRect(Instance, Child, out int Left, out int Top, out _, out _);
                ulong LParam = WinSysHelper.PackCoordinates(Left, Top);

                if (IsOwnedByCurrentThread(Instance, Child)
                    && InvokeWindowProc(Instance, Child.Hwnd, Child.WndProc, WM_MOVE, 0, LParam, ScrollChildMoves: Moves))
                {
                    return true;
                }

                PostMessage(Instance, Child.Hwnd, WM_MOVE, 0, LParam);
            }

            return false;
        }

        // NT: prcUpdate is written after WM_MOVE, and a fault there fails the call.
        internal static ulong FinishScrollWindow(BinaryEmulator Instance, ulong UpdateAddress, in GdiClipRect UpdateRect, int Result)
        {
            if (UpdateAddress != 0 && !TryWriteGuestRect(Instance, UpdateAddress, UpdateRect))
            {
                Instance.SetLastWinError(ERROR_NOACCESS);
                return 0;
            }

            return (uint)Result;
        }

        private static void MoveDcBits(BinaryEmulator Instance, Win32kDeviceContext Dc, ulong Hdc, List<GdiClipRect> Area, int Dx, int Dy)
        {
            if (!TryGetDcBitmap(Instance, Hdc, out Win32kBitmap Bitmap) || !CanBlitBitmap(Bitmap))
            {
                if (Dc.Hwnd != 0)
                    Instance.WinHelper.EnqueueGdiCopy(Dc.Hwnd, Area, Dx, Dy);

                return;
            }

            GetRegionBounds(Area, out GdiClipRect Box);
            int Width = Box.Right - Box.Left;
            int Height = Box.Bottom - Box.Top;
            if (!IsBlitExtentValid(Width, Height))
                return;

            // The source is read whole before any write, so an overlap reads no copied pixels.
            uint[] Rented = ArrayPool<uint>.Shared.Rent(Width * Height);
            try
            {
                Span<uint> Block = Rented.AsSpan(0, Width * Height);
                if (TryReadBitmapBlock(Instance, Bitmap, Box.Left - Dx, Box.Top - Dy, Width, Height, Block))
                    TryBlitBlockIntoBitmap(Instance, Bitmap, Box.Left, Box.Top, Width, Height, Block, Width, Height, SrcCopyRop, 0, Area.ToArray());
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Rented);
            }
        }

        // NT: a faulting RECT probe fails the call with ERROR_NOACCESS.
        internal static bool TryReadOptionalRect(BinaryEmulator Instance, ulong Address, out GdiClipRect? Rect)
        {
            Rect = null;
            if (Address == 0)
                return true;

            if (!TryReadGuestRect(Instance, Address, out GdiClipRect Value))
                return false;

            Rect = Value;
            return true;
        }

        internal static bool TryReadGuestRect(BinaryEmulator Instance, ulong Address, out GdiClipRect Rect)
        {
            Rect = default;

            Span<byte> Buffer = stackalloc byte[GuestRectSize];
            if (Address == 0 || !Instance.ReadMemory(Address, Buffer))
                return false;

            Rect = new GdiClipRect
            {
                Left = BinaryPrimitives.ReadInt32LittleEndian(Buffer),
                Top = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(4)),
                Right = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(8)),
                Bottom = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(12)),
            };
            return true;
        }

        internal static bool TryReadGuestRect(BinaryEmulator Instance, ulong Address, List<GdiClipRect> Area)
        {
            if (!TryReadGuestRect(Instance, Address, out GdiClipRect Rect))
                return false;

            Area.Add(Rect);
            return true;
        }

        internal const int GuestRectSize = 16;

        internal static void WriteGuestRect(Span<byte> Buffer, in GdiClipRect Rect)
        {
            BinaryPrimitives.WriteInt32LittleEndian(Buffer, Rect.Left);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4), Rect.Top);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(8), Rect.Right);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(12), Rect.Bottom);
        }

        internal static bool TryWriteGuestRect(BinaryEmulator Instance, ulong Address, in GdiClipRect Rect)
        {
            Span<byte> Buffer = stackalloc byte[GuestRectSize];
            WriteGuestRect(Buffer, Rect);
            return Instance.WriteMemory(Address, Buffer);
        }

        // Screen coordinates.
        internal static void GetScreenRects(BinaryEmulator Instance, WinWindow Window, out GdiClipRect WindowRect, out GdiClipRect ClientRect)
        {
            GetAbsoluteWindowPosition(Instance, Window, out int Left, out int Top);
            GetScreenRects(Instance, Window, Left, Top, out WindowRect, out ClientRect);
        }

        private static void GetScreenRects(BinaryEmulator Instance, WinWindow Window, int Left, int Top, out GdiClipRect WindowRect, out GdiClipRect ClientRect)
        {
            GetFrameInsets(Instance, Window, out int InsetLeft, out int InsetTop, out int InsetRight, out int InsetBottom);
            WindowRect = MakeRect(Left, Top, Window.Width, Window.Height);
            ClientRect = new GdiClipRect
            {
                Left = SaturatingAdd(WindowRect.Left, InsetLeft),
                Top = SaturatingAdd(WindowRect.Top, InsetTop),
                Right = Math.Max(SaturatingAdd(WindowRect.Right, -InsetRight), SaturatingAdd(WindowRect.Left, InsetLeft)),
                Bottom = Math.Max(SaturatingAdd(WindowRect.Bottom, -InsetBottom), SaturatingAdd(WindowRect.Top, InsetTop)),
            };
        }

        private static GdiClipRect ToClientRect(in GdiClipRect ClientRect)
        {
            return new GdiClipRect
            {
                Right = (int)Math.Min((long)ClientRect.Right - ClientRect.Left, int.MaxValue),
                Bottom = (int)Math.Min((long)ClientRect.Bottom - ClientRect.Top, int.MaxValue),
            };
        }

        private static GdiClipRect MakeRect(int Left, int Top, uint Width, uint Height)
        {
            return new GdiClipRect { Left = Left, Top = Top, Right = SaturatingAdd(Left, Width), Bottom = SaturatingAdd(Top, Height) };
        }

        internal static GdiClipRect ShiftRect(in GdiClipRect Rect, long X, long Y)
        {
            return new GdiClipRect
            {
                Left = SaturatingAdd(Rect.Left, X),
                Top = SaturatingAdd(Rect.Top, Y),
                Right = SaturatingAdd(Rect.Right, X),
                Bottom = SaturatingAdd(Rect.Bottom, Y),
            };
        }

        private static int SaturatingAdd(int Value, long Offset)
        {
            return (int)Math.Clamp(Value + Offset, int.MinValue, int.MaxValue);
        }

        internal static GdiClipRect Intersect(in GdiClipRect A, in GdiClipRect B)
        {
            return new GdiClipRect
            {
                Left = Math.Max(A.Left, B.Left),
                Top = Math.Max(A.Top, B.Top),
                Right = Math.Min(A.Right, B.Right),
                Bottom = Math.Min(A.Bottom, B.Bottom),
            };
        }

        internal static bool IsEmpty(in GdiClipRect Rect)
        {
            return Rect.Right <= Rect.Left || Rect.Bottom <= Rect.Top;
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
        internal static bool InvokeWindowProc(BinaryEmulator Instance, ulong Hwnd, ulong WndProc, uint Message, ulong WParam, ulong LParam, WinWindowCreation Creation = null, ulong SyscallRetryRip = 0, ulong PaintRetryHwnd = 0,
            WinPaintBegin PaintBegin = null, WinScrollChildMoves ScrollChildMoves = null, ulong? DeferredSyscallResult = null)
        {
            if (!TryBeginWindowProcCallback(Instance, WndProc, out ulong Callback, out ulong ArgumentBuffer))
                return false;

            WriteWindowProcCallbackArguments(Instance, ArgumentBuffer, Hwnd, WndProc, Message, WParam, LParam);
            return Instance.WinHelper.EnterUserCallback(Callback, WindowProcCallbackIndex, ArgumentBuffer, Creation, SyscallRetryRip, PaintRetryHwnd,
                PaintBegin: PaintBegin, ScrollChildMoves: ScrollChildMoves, DeferredSyscallResult: DeferredSyscallResult);
        }

        // True once, for the syscall that the returning WM_PAINT callback is re-running.
        internal static bool TakePaintRetry(BinaryEmulator Instance, ulong Hwnd)
        {
            if (Hwnd == 0)
                return false;

            WindowsThreadState State = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            if (State == null || State.PendingPaintRetryHwnd != Hwnd)
                return false;

            State.PendingPaintRetryHwnd = 0;
            return true;
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

        internal static bool SendWindowDestroyMessage(BinaryEmulator Instance, WinWindow Window, uint Message, WinWindowDestruction Destruction)
        {
            if (Window == null || !TryBeginWindowProcCallback(Instance, Window.WndProc, out ulong Callback, out ulong ArgumentBuffer))
                return false;

            WriteWindowProcCallbackArguments(Instance, ArgumentBuffer, Window.Hwnd, Window.WndProc, Message, 0, 0);
            return Instance.WinHelper.EnterUserCallback(Callback, WindowProcCallbackIndex, ArgumentBuffer, null, Destruction: Destruction);
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

        internal static ulong HandleMessageCall(BinaryEmulator Instance, ulong Hwnd, uint Message, ulong WParam, ulong LParam, bool Ansi, out bool Deferred)
        {
            Deferred = false;

            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                return 0;
            }

            WinWindow Window = Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return 0;

            return DefaultWindowProc(Instance, Window, Message, WParam, LParam, Ansi, out Deferred);
        }

        private static ulong DefaultWindowProc(BinaryEmulator Instance, WinWindow Window, uint Message, ulong WParam, ulong LParam, bool Ansi, out bool Deferred)
        {
            Deferred = false;

            switch (Message)
            {
                // NT: nothing is invalidated.
                case WM_SETTEXT:
                    Window.Title = ReadWindowTextPointer(Instance, LParam, Ansi) ?? string.Empty;
                    Instance.WinHelper.MaterializeUserWindow(Window);
                    Instance.WinHelper.PresentDesktop();
                    return 1;

                case WM_SETREDRAW:
                    SetRedraw(Instance, Window, WParam != 0);
                    return 0;

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
                    Instance.WinHelper.DestroyWindow(Window.Hwnd, 0, out Deferred);
                    return 0;

                default:
                    if (Message >= WM_CTLCOLORMSGBOX && Message <= WM_CTLCOLORSTATIC)
                        return Instance.WinHelper.GetSystemColorBrush(DefaultControlColorIndex(Message));

                    return 0;
            }
        }

        // NT: xxxDWP_SetRedraw. TRUE shows the window with nothing to paint.
        private static void SetRedraw(BinaryEmulator Instance, WinWindow Window, bool Redraw)
        {
            const uint WS_VISIBLE = 0x10000000;

            if (Redraw == Window.Visible)
                return;

            if (!Redraw)
                ClearUpdateTree(Instance, Window);

            Window.Visible = Redraw;
            Window.RedrawDisabled = !Redraw;
            Window.Style = Redraw ? Window.Style | WS_VISIBLE : Window.Style & ~WS_VISIBLE;
            Instance.WinHelper.MaterializeUserWindow(Window);
            Instance.WinHelper.PresentDesktop();
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

            GetClientSize(Instance, Window, out int ClientWidth, out int ClientHeight);
            Instance.WinHelper.EnqueueGdiFillRect(Window.Hwnd, Hdc, 0, 0, ClientWidth, ClientHeight, Color, PatCopy);
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

        // win32kfull!CalcWakeMask. Any input bit wakes on all input. Posted, timer and hotkey wake together.
        internal static uint WakeMaskFromPeekFlags(uint Flags)
        {
            uint Filter = Flags >> 16;
            if (Filter == 0)
                return QS_ALLINPUT;

            if ((Filter & QS_INPUT) != 0)
                Filter |= QS_INPUT;

            if ((Filter & (QS_POSTMESSAGE | QS_TIMER | QS_HOTKEY)) != 0)
                Filter |= QS_POSTMESSAGE | QS_TIMER | QS_HOTKEY;

            return Filter;
        }

        // Stands in for a sent message, so only a reader of sent messages gets it.
        private static uint GetQueuedMessageWakeBits(in Win32kMessage Message)
        {
            return Message.Notification ? QS_SENDMESSAGE : GetMessageWakeBits(Message.Message);
        }

        private static bool MatchesFilter(BinaryEmulator Instance, Win32kMessage Message, ulong HwndFilter, uint MinMessage, uint MaxMessage, uint ThreadId)
        {
            if (HwndFilter != 0 && Message.Hwnd != HwndFilter)
                return false;

            if (!OwnedByThread(Instance, Message, ThreadId))
                return false;

            if (MinMessage == 0 && MaxMessage == 0)
                return true;

            return Message.Message >= MinMessage && Message.Message <= MaxMessage;
        }

        // A thread message names its reader outright, a window message is read by the thread that owns it.
        private static bool OwnedByThread(BinaryEmulator Instance, in Win32kMessage Message, uint ThreadId)
        {
            if (Message.TargetThreadId != 0)
                return ThreadId == 0 || Message.TargetThreadId == ThreadId;

            return OwnedByThread(Instance, Message.Hwnd, ThreadId);
        }

        // Only the creating thread may run a window procedure, so another thread's message stays queued.
        private static bool OwnedByThread(BinaryEmulator Instance, ulong Hwnd, uint ThreadId)
        {
            if (Hwnd == 0 || ThreadId == 0)
                return true;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            return Window == null || Window.OwnerThreadId == 0 || Window.OwnerThreadId == ThreadId;
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
                SetExStyle(Window, Composed & ~WinSysHelper.UserWindowStateVisible);
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
            Previous = Instance.WinHelper.ReadPointer(Address, Size);
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
