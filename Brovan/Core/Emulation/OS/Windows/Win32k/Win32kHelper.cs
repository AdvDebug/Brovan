using System.Buffers.Binary;
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

    internal static class Win32kHelper
    {
        internal const uint ERROR_INVALID_PARAMETER = 87;
        internal const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
        internal const uint ERROR_INVALID_WINDOW_HANDLE = 1400;
        internal const uint DEFAULT_SCREEN_DPI = 96;

        internal const byte PenHandleType = 0x30;
        internal const byte BrushHandleType = 0x10;

        internal const uint WM_NULL = 0x0000;
        internal const uint WM_DESTROY = 0x0002;
        internal const uint WM_CLOSE = 0x0010;
        internal const uint WM_QUIT = 0x0012;
        internal const uint WM_ERASEBKGND = 0x0014;
        internal const uint WM_SETCURSOR = 0x0020;
        internal const uint WM_GETTEXT = 0x000D;
        internal const uint WM_GETTEXTLENGTH = 0x000E;
        internal const uint WM_NCHITTEST = 0x0084;
        internal const uint WM_NCDESTROY = 0x0082;
        internal const uint WM_PAINT = 0x000F;
        internal const uint WM_SETTEXT = 0x000C;
        internal const uint WM_KEYDOWN = 0x0100;
        internal const uint WM_KEYUP = 0x0101;
        internal const uint WM_CHAR = 0x0102;
        internal const uint WM_SYSKEYDOWN = 0x0104;
        internal const uint WM_SYSKEYUP = 0x0105;
        internal const uint WM_SYSCHAR = 0x0106;
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

        private const int HTCLIENT = 1;
        private const ulong HWND_BROADCAST = 0xFFFF;
        private const ulong FirstDeviceContextHandle = 0x770001;
        private const uint PM_REMOVE = 0x0001;
        private const int MSG64_SIZE = 48;
        private const int PAINTSTRUCT64_SIZE = 72;
        private const int MaxWindowTextBytes = 0x1000;

        private static readonly ConditionalWeakTable<BinaryEmulator, Win32kState> States = new();

        private sealed class Win32kState
        {
            public readonly Queue<Win32kMessage> MessageQueue = new();
            public readonly Dictionary<ulong, Win32kDeviceContext> DeviceContexts = new();
            public readonly Dictionary<ulong, Win32kPenBrush> PenBrushObjects = new();
            public ulong NextDeviceContext = FirstDeviceContextHandle;
            public ulong CaptureWindow;
            public bool QuitPosted;
            public ulong QuitExitCode;
        }

        private sealed class Win32kDeviceContext
        {
            public ulong Handle;
            public ulong Hwnd;
            public bool WindowDc;
            public bool PaintDc;
        }

        private static Win32kState GetState(BinaryEmulator Instance)
        {
            return States.GetValue(Instance, static _ => new Win32kState());
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

            Win32kState State = GetState(Instance);
            State.DeviceContexts[GdiHandle] = new Win32kDeviceContext
            {
                Handle = GdiHandle,
                Hwnd = Hwnd,
                WindowDc = WindowDc,
                PaintDc = PaintDc,
            };
            return GdiHandle;
        }

        internal static bool ReleaseDeviceContext(BinaryEmulator Instance, ulong Hdc)
        {
            if (Hdc == 0)
                return false;

            Win32kState State = GetState(Instance);
            return State.DeviceContexts.Remove(Hdc);
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

        internal static bool RemovePenBrush(BinaryEmulator Instance, ulong Handle)
        {
            return GetState(Instance).PenBrushObjects.Remove(Handle);
        }

        internal static bool PostMessage(BinaryEmulator Instance, ulong Hwnd, uint Message, ulong WParam, ulong LParam)
        {
            Win32kState State = GetState(Instance);
            uint Time = unchecked((uint)Instance.EmulatedTickCount64);

            if (Hwnd == HWND_BROADCAST)
            {
                foreach (ulong TargetHwnd in Instance.WinHelper.TopLevelWindows)
                {
                    if (Instance.WinHelper.GetWindow(TargetHwnd) != null)
                        State.MessageQueue.Enqueue(new Win32kMessage(TargetHwnd, Message, WParam, LParam, Time, 0, 0));
                }

                return true;
            }

            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
                return false;

            State.MessageQueue.Enqueue(new Win32kMessage(Hwnd, Message, WParam, LParam, Time, 0, 0));
            return true;
        }

        internal static void PostQuitMessage(BinaryEmulator Instance, ulong ExitCode)
        {
            Win32kState State = GetState(Instance);
            State.QuitExitCode = ExitCode;
            State.QuitPosted = true;
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
                        RemoveMessageAt(State.MessageQueue, Index);
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
            DrainHostEvents(Instance);

            if (WakeMask == 0)
                return false;

            Win32kState State = GetState(Instance);
            if (State.QuitPosted && (WakeMask & QS_POSTMESSAGE) != 0)
                return true;

            foreach (Win32kMessage Candidate in State.MessageQueue)
            {
                if ((GetMessageWakeBits(Candidate.Message) & WakeMask) != 0)
                    return true;
            }

            return false;
        }

        private static uint GetMessageWakeBits(uint Message)
        {
            switch (Message)
            {
                case WM_PAINT:
                    return QS_PAINT;
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

        internal static bool WriteMessage(BinaryEmulator Instance, ulong Address, Win32kMessage Message)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, MSG64_SIZE))
                return false;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(MSG64_SIZE);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Message.Hwnd);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), Message.Message);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), Message.WParam);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), Message.LParam);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x20, 4), Message.Time);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x24, 4), Message.X);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x28, 4), Message.Y);
            return Instance.WriteMemory(Address, Buffer.Slice(0, MSG64_SIZE));
        }

        internal static bool TryReadMessage(BinaryEmulator Instance, ulong Address, out Win32kMessage Message)
        {
            Message = default;
            if (Address == 0 || !Instance.IsRegionMapped(Address, MSG64_SIZE))
                return false;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(MSG64_SIZE);
            if (!Instance.ReadMemory(Address, Buffer.Slice(0, MSG64_SIZE), MSG64_SIZE))
                return false;

            Message = new Win32kMessage(
                BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(0x00, 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x08, 4)),
                BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(0x10, 8)),
                BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(0x18, 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x20, 4)),
                BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x24, 4)),
                BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x28, 4)));
            return true;
        }

        internal static bool WritePaintStruct(BinaryEmulator Instance, ulong PaintStructPtr, ulong Hdc, WinWindow Window)
        {
            if (PaintStructPtr == 0 || !Instance.IsRegionMapped(PaintStructPtr, PAINTSTRUCT64_SIZE))
                return false;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(PAINTSTRUCT64_SIZE);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Hdc);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x08, 4), 1);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x0C, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x10, 4), 0);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x14, 4), (int)Math.Min(Window.Width, (uint)int.MaxValue));
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x18, 4), (int)Math.Min(Window.Height, (uint)int.MaxValue));
            return Instance.WriteMemory(PaintStructPtr, Buffer.Slice(0, PAINTSTRUCT64_SIZE));
        }

        internal static ulong DispatchMessage(BinaryEmulator Instance, Win32kMessage Message)
        {
            WinWindow Window = Message.Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Message.Hwnd);
            if (Message.Hwnd != 0 && Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                return 0;
            }

            if (Window != null)
            {
                switch (Message.Message)
                {
                    case WM_SETTEXT:
                        Window.Title = ReadWindowTextPointer(Instance, Message.LParam, false) ?? string.Empty;
                        Window.Dirty = true;
                        Instance.WinHelper.MaterializeUserWindow(Window);
                        Instance.WinHelper.PresentDesktop();
                        return 1;

                    case WM_GETTEXT:
                        return WriteWindowText(Instance, Window.Title ?? string.Empty, Message.LParam, Message.WParam, false);

                    case WM_GETTEXTLENGTH:
                        return (ulong)(Window.Title?.Length ?? 0);

                    case WM_NCHITTEST:
                        return HTCLIENT;

                    case WM_ERASEBKGND:
                        return 1;

                    case WM_CLOSE:
                        Instance.WinHelper.DestroyWindow(Window.Hwnd);
                        return 0;

                    case WM_DESTROY:
                    case WM_SETCURSOR:
                    case WM_PAINT:
                    case WM_NULL:
                    default:
                        return 0;
                }
            }

            return 0;
        }

        private const int MaxHostInputEventsPerDrain = 64;

        private static void DrainHostEvents(BinaryEmulator Instance)
        {
            ulong Foreground = Instance.WinHelper.GetForegroundWindow();

            if (HostEventQueue.ConsumeRepaint() && Foreground != 0)
                InvalidateWindow(Instance, Foreground);

            if (Foreground == 0)
                return;

            for (int i = 0; i < MaxHostInputEventsPerDrain; i++)
            {
                if (!HostEventQueue.TryDequeue(out uint Message, out ulong WParam, out ulong LParam))
                    break;

                PostMessage(Instance, Foreground, Message, WParam, LParam);
            }
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

            if (Message == WM_SETTEXT)
            {
                Window.Title = ReadWindowTextPointer(Instance, LParam, Ansi) ?? string.Empty;
                Window.Dirty = true;
                Instance.WinHelper.MaterializeUserWindow(Window);
                Instance.WinHelper.PresentDesktop();
                return 1;
            }

            if (Message == WM_GETTEXT)
                return WriteWindowText(Instance, Window.Title ?? string.Empty, LParam, WParam, Ansi);

            if (Message == WM_GETTEXTLENGTH)
                return (ulong)(Window.Title?.Length ?? 0);

            if (Message == WM_NCHITTEST)
                return HTCLIENT;

            if (Message == WM_ERASEBKGND)
                return 1;

            if (Message == WM_CLOSE)
            {
                Instance.WinHelper.DestroyWindow(Window.Hwnd);
                return 0;
            }

            return 0;
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

        private static void RemoveMessageAt(Queue<Win32kMessage> Queue, int Index)
        {
            int Count = Queue.Count;
            for (int i = 0; i < Count; i++)
            {
                Win32kMessage Message = Queue.Dequeue();
                if (i != Index)
                    Queue.Enqueue(Message);
            }
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
    }
}
