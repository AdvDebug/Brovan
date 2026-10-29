using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.OS.SharedHelpers;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Helpers;

namespace Brovan.Android
{
    internal sealed class AndroidTerminal : IHostTerminal
    {
        private const int DefaultColumns = 80;
        private const int DefaultRows = 25;
        private const char ControlC = (char)0x03;

        public static readonly AndroidTerminal Shared = new AndroidTerminal();

        private static readonly Encoding Utf8 = new UTF8Encoding(false);

        private readonly object _create = new();
        private TerminalScreen _screen;
        private int _attached;
        private volatile bool _controlCAsInput;

        // Delay screen allocation until the memory profile is set.
        private TerminalScreen Screen
        {
            get
            {
                TerminalScreen screen = Volatile.Read(ref _screen);
                if (screen != null)
                    return screen;

                lock (_create)
                {
                    if (_screen == null)
                        Volatile.Write(ref _screen, new TerminalScreen(DefaultColumns, DefaultRows));

                    return _screen;
                }
            }
        }

        public HostStreamTarget Stream(HostStreamKind Kind)
        {
            if (AndroidHost.HasPlayer)
                return HostStreamTarget.Console;

            return Kind == HostStreamKind.Input ? HostStreamTarget.Null : HostStreamTarget.Pipe;
        }

        public Encoding Encoding => Utf8;

        public void Write(ReadOnlySpan<byte> data, GuestConsoleOutputMode mode, uint outputMode)
        {
            if (mode == GuestConsoleOutputMode.Suppressed || data.IsEmpty)
                return;

            Screen.Write(data, outputMode);
            PostReplies();
            Publish();
        }

        public TerminalGeometry Geometry
        {
            get
            {
                TerminalGeometry geometry = Screen.Geometry;
                Publish();
                return geometry;
            }
        }

        public void MoveCursor(int x, int y)
        {
            Screen.MoveCursor(x, y);
            Publish();
        }

        public int Fill(int x, int y, char element, int count, GuestConsoleOutputMode mode)
        {
            int cells = Screen.Fill(x, y, element, count);
            Publish();
            return cells;
        }

        public ushort Attributes
        {
            get => Screen.Attributes;
            set => Screen.Attributes = value;
        }

        public uint CursorSize
        {
            get => Screen.CursorSize;
            set => Screen.CursorSize = value;
        }

        public bool CursorVisible
        {
            get => Screen.CursorVisible;
            set
            {
                Screen.CursorVisible = value;
                Publish();
            }
        }

        public bool CursorKeysApplication => Screen.CursorKeysApplication;

        public void StartInput()
        {
        }

        public void RequestInput(bool blocking, Task seen)
        {
        }

        public void SetControlCAsInput(bool value) => _controlCAsInput = value;

        public void Attach()
        {
            if (!AndroidHost.HasPlayer || Interlocked.Exchange(ref _attached, 1) != 0)
                return;

            GeneralHelper.HostConsoleInput.MarkProducing();
            AndroidHost.NotifyPlayer(AndroidHost.PlayerConsoleAttached);
        }

        public void Key(bool down, ushort virtualKey, char character, uint controlKeyState)
        {
            if (character == ControlC && !_controlCAsInput)
            {
                // Keep session-lock waits off the UI thread.
                if (down)
                    ThreadPool.QueueUserWorkItem(_ => EndWithControlC());
                return;
            }

            GeneralHelper.HostConsoleInput.PostKey(HostInputEvent.Key(down, virtualKey, character, controlKeyState & HostInputEvent.KnownStateBits));
        }

        public void Resize(int columns, int rows)
        {
            Screen.RequestResize(columns, rows);
            Publish();
        }

        public int Snapshot(Span<int> destination, int scrollBack)
        {
            int written = Screen.Snapshot(destination, scrollBack);
            Publish();
            return written;
        }

        private static void EndWithControlC()
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return;

            const uint exitCode = (uint)NTSTATUS.STATUS_CONTROL_C_EXIT;
            GuestSession.PublishExit(exitCode);
            Utils.SetGuestExitCode(exitCode);
            emulator.RequestTermination();
        }

        private void PostReplies()
        {
            string replies = Screen.TakeReplies();
            if (replies != null)
                GeneralHelper.HostConsoleInput.PostText(replies);
        }

        private void Publish()
        {
            TerminalScreen screen = Screen;
            if (screen.TakeResize(out ushort columns, out ushort rows))
                GeneralHelper.HostConsoleInput.Post(HostInputEvent.Resize(columns, rows));

            if (screen.TakeChange())
                AndroidHost.NotifyPlayer(AndroidHost.PlayerScreenChanged);
        }
    }
}
