using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.Windows;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public enum HostStreamTarget : byte
    {
        Console,
        Pipe,
        Null
    }

    public enum HostInputKind : byte
    {
        Key,
        Resize
    }

    public struct HostInputEvent
    {
        public const uint RightAltPressed = 0x0001;
        public const uint LeftAltPressed = 0x0002;
        public const uint RightCtrlPressed = 0x0004;
        public const uint LeftCtrlPressed = 0x0008;
        public const uint ShiftPressed = 0x0010;
        public const uint EnhancedKey = 0x0100;
        public const uint KnownStateBits = 0x01FF;

        public HostInputKind Kind;
        public bool KeyDown;
        public ushort RepeatCount;
        public ushort VirtualKey;
        public ushort ScanCode;
        public char Character;
        public uint ControlKeyState;
        public ushort Columns;
        public ushort Rows;

        public static HostInputEvent Key(bool Down, ushort VirtualKey, char Character, uint ControlKeyState)
        {
            return new HostInputEvent
            {
                Kind = HostInputKind.Key,
                KeyDown = Down,
                RepeatCount = 1,
                VirtualKey = VirtualKey,
                Character = Character,
                ControlKeyState = ControlKeyState
            };
        }

        public static HostInputEvent Resize(ushort Columns, ushort Rows)
        {
            return new HostInputEvent { Kind = HostInputKind.Resize, Columns = Columns, Rows = Rows };
        }
    }

    public struct TerminalGeometry
    {
        public ushort BufferWidth;
        public ushort BufferHeight;
        public ushort CursorX;
        public ushort CursorY;
        public ushort WindowLeft;
        public ushort WindowTop;
        public ushort WindowWidth;
        public ushort WindowHeight;
        public ushort LargestWidth;
        public ushort LargestHeight;
    }

    public interface IHostTerminal
    {
        HostStreamTarget Stream(HostStreamKind Kind);

        Encoding Encoding { get; }

        void Write(ReadOnlySpan<byte> Data, GuestConsoleOutputMode Mode, uint OutputMode);

        TerminalGeometry Geometry { get; }

        void MoveCursor(int X, int Y);

        int Fill(int X, int Y, char Element, int Count, GuestConsoleOutputMode Mode);

        ushort Attributes { get; set; }

        uint CursorSize { get; set; }

        bool CursorVisible { get; set; }

        bool CursorKeysApplication { get; }

        void StartInput();

        // Capture Seen from HostConsoleInput.NextInput before polling input.
        void RequestInput(bool Blocking, Task Seen);

        void SetControlCAsInput(bool Value);

        void Attach();
    }

    public static class HostTerminal
    {
        private static readonly object CreateLock = new();
        private static IHostTerminal _current;

        public static IHostTerminal Current => Volatile.Read(ref _current) ?? Create();

        private static IHostTerminal Create()
        {
            lock (CreateLock)
            {
                if (_current == null)
                    Volatile.Write(ref _current, Android.AndroidHost.IsActive ? Android.AndroidTerminal.Shared : new SystemConsoleTerminal());

                return _current;
            }
        }
    }
}
