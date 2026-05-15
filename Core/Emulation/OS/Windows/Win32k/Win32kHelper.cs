using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;
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

    internal static class Win32kHelper
    {
        internal const uint ERROR_INVALID_PARAMETER = 87;
        internal const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
        internal const uint ERROR_INVALID_WINDOW_HANDLE = 1400;
        internal const uint DEFAULT_SCREEN_DPI = 96;

        internal const uint WM_NULL = 0x0000;
        internal const uint WM_DESTROY = 0x0002;
        internal const uint WM_CLOSE = 0x0010;
        internal const uint WM_QUIT = 0x0012;
        internal const uint WM_ERASEBKGND = 0x0014;
        internal const uint WM_SETCURSOR = 0x0020;
        internal const uint WM_GETTEXT = 0x000D;
        internal const uint WM_GETTEXTLENGTH = 0x000E;
        internal const uint WM_NCHITTEST = 0x0084;
        internal const uint WM_PAINT = 0x000F;
        internal const uint WM_SETTEXT = 0x000C;

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
            public ulong NextDeviceContext = FirstDeviceContextHandle;
            public ulong CaptureWindow;
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

            Win32kState State = GetState(Instance);
            ulong Handle = State.NextDeviceContext;
            State.NextDeviceContext += 4;
            State.DeviceContexts[Handle] = new Win32kDeviceContext
            {
                Handle = Handle,
                Hwnd = Hwnd,
                WindowDc = WindowDc,
                PaintDc = PaintDc,
            };
            return Handle;
        }

        internal static bool ReleaseDeviceContext(BinaryEmulator Instance, ulong Hdc)
        {
            if (Hdc == 0)
                return false;

            Win32kState State = GetState(Instance);
            return State.DeviceContexts.Remove(Hdc);
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

        internal static bool TryGetMessage(BinaryEmulator Instance, ulong HwndFilter, uint MinMessage, uint MaxMessage, bool Remove, out Win32kMessage Message)
        {
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

            Message = default;
            return false;
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
