using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.Windows;
using static Brovan.Core.Helpers.Utils;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public sealed class SystemConsoleTerminal : IHostTerminal
    {
        private const int ForcedExitPresses = 3;
        private const long ForcedExitWindowMilliseconds = 2000;
        private const ushort DefaultBufferWidth = 120;
        private const ushort DefaultBufferHeight = 30;
        private const uint EnableVirtualTerminalProcessing = 0x0004;
        private const ushort VkReturn = 0x0D;
        private const int RepeatChunkBytes = 16384;

        private const int DemandNone = 0;
        private const int DemandIfReady = 1;
        private const int DemandBlocking = 2;

        private static readonly object Gate = new object();
        private static readonly object PromptGate = new object();
        private static readonly SemaphoreSlim DemandSignal = new SemaphoreSlim(0);
        private static HostInputEvent PendingPrompt;
        private static bool HasPendingPrompt;
        private static Thread Reader;
        private static int Demand;
        private static Task DemandFor;
        private static bool ControlCSaved;
        private static bool SavedControlCAsInput;
        private static int ControlCPresses;
        private static long FirstControlCTick;

        private enum OutputParse
        {
            Ground,
            Escape,
            CsiStart,
            PrivateParameters
        }

        private readonly object TrackGate = new object();
        private OutputParse OutputState;
        private int OutputParameter;
        private bool OutputParameterHasOne;
        private volatile bool CursorKeysApplicationMode;

        private ushort CursorX;
        private ushort CursorY;

        public ushort Attributes { get; set; } = 0x0007;

        public uint CursorSize { get; set; } = 25;

        public bool CursorVisible { get; set; } = true;

        public bool CursorKeysApplication => CursorKeysApplicationMode;

        private static bool ReaderRunning => Volatile.Read(ref Reader) != null;

        private static bool HostConsoleUsable => !Console.IsOutputRedirected;

        public HostStreamTarget Stream(HostStreamKind Kind)
        {
            bool Redirected = Kind switch
            {
                HostStreamKind.Input => Console.IsInputRedirected,
                HostStreamKind.Error => Console.IsErrorRedirected,
                _ => Console.IsOutputRedirected,
            };

            if (!Redirected)
                return HostStreamTarget.Console;

            return IsHostNullDevice(Kind) ? HostStreamTarget.Null : HostStreamTarget.Pipe;
        }

        public Encoding Encoding
        {
            get
            {
                try
                {
                    return Console.OutputEncoding ?? Encoding.UTF8;
                }
                catch
                {
                    return Encoding.UTF8;
                }
            }
        }

        public void Write(ReadOnlySpan<byte> Data, GuestConsoleOutputMode Mode, uint OutputMode)
        {
            if ((OutputMode & EnableVirtualTerminalProcessing) != 0)
                TrackCursorKeys(Data);

            GeneralHelper.ConsoleWrite(Data, Mode);
        }

        public TerminalGeometry Geometry
        {
            get
            {
                ReadHostGeometry(out ushort Width, out ushort Height, out ushort HostCursorX, out ushort HostCursorY);
                TerminalGeometry Result = new TerminalGeometry
                {
                    BufferWidth = Width,
                    BufferHeight = Height,
                    CursorX = HostConsoleUsable ? HostCursorX : CursorX,
                    CursorY = HostConsoleUsable ? HostCursorY : CursorY,
                };

                ReadHostWindow(Width, Height, out Result.WindowLeft, out Result.WindowTop, out Result.WindowWidth, out Result.WindowHeight,
                    out Result.LargestWidth, out Result.LargestHeight);
                return Result;
            }
        }

        public void MoveCursor(int X, int Y)
        {
            CursorX = (ushort)Math.Clamp(X, 0, ushort.MaxValue);
            CursorY = (ushort)Math.Clamp(Y, 0, ushort.MaxValue);
            MoveHostCursor(X, Y);
        }

        public int Fill(int X, int Y, char Element, int Count, GuestConsoleOutputMode Mode)
        {
            ReadHostGeometry(out ushort Width, out ushort Height, out _, out _);
            if (X < 0 || Y < 0 || X >= Width || Y >= Height || Count <= 0)
                return 0;

            int Cells = (int)Math.Min((long)(Height - Y) * Width - X, Count);
            if (!HostConsoleUsable)
                return Cells;

            try
            {
                int SavedX = Console.CursorLeft;
                int SavedY = Console.CursorTop;

                MoveHostCursor(X, Y);
                WriteRepeated(Element, Cells, Mode);
                MoveHostCursor(SavedX, SavedY);
            }
            catch (IOException Ex)
            {
                LogError($"Host console fill failed: {Ex.Message}");
                return 0;
            }

            return Cells;
        }

        public void StartInput()
        {
            if (ReaderRunning)
                return;

            lock (Gate)
            {
                if (Reader != null)
                    return;

                Thread Worker = new Thread(Console.IsInputRedirected ? ReadLines : ReadKeys)
                {
                    IsBackground = true,
                    Name = "Brovan console input"
                };
                Worker.Start();
                Volatile.Write(ref Reader, Worker);
                GeneralHelper.HostConsoleInput.MarkProducing();
            }
        }

        // Console processes share input. Read only on demand.
        public void RequestInput(bool Blocking, Task Seen) => RequestDemand(Blocking, Seen);

        public void SetControlCAsInput(bool Value)
        {
            if (Console.IsInputRedirected)
                return;

            lock (Gate)
            {
                try
                {
                    if (!ControlCSaved)
                    {
                        SavedControlCAsInput = Console.TreatControlCAsInput;
                        ControlCSaved = true;
                        AppDomain.CurrentDomain.ProcessExit += RestoreControlC;
                        AppDomain.CurrentDomain.UnhandledException += RestoreControlC;
                    }

                    if (Console.TreatControlCAsInput != Value)
                        Console.TreatControlCAsInput = Value;
                }
                catch (IOException Ex)
                {
                    LogError($"Host console Ctrl+C mode could not be changed: {Ex.Message}");
                }
            }
        }

        public void Attach()
        {
        }

        public static bool PromptKeyAvailable =>
            ReaderRunning ? HasQueuedKeyDown() || (!Console.IsInputRedirected && Console.KeyAvailable) : Console.KeyAvailable;

        public static ConsoleKeyInfo ReadPromptKey()
        {
            if (!ReaderRunning)
                return Console.ReadKey(true);

            while (true)
            {
                HostInputEvent Event;
                bool Held;
                lock (PromptGate)
                {
                    Held = HasPendingPrompt;
                    Event = PendingPrompt;
                    HasPendingPrompt = false;
                }

                if (Held)
                    return FinishPress(in Event);

                Task Seen = GeneralHelper.HostConsoleInput.NextInput;
                if (!GeneralHelper.HostConsoleInput.TryTake(out Event))
                {
                    if (!RequestDemand(true, Seen))
                        continue;

                    if (!GeneralHelper.HostConsoleInput.Take(out Event))
                        throw new InvalidOperationException("The host console input has ended.");
                }

                if (IsKeyDown(in Event))
                    return FinishPress(in Event);
            }
        }

        public static string ReadPromptLine()
        {
            if (!ReaderRunning)
                return Console.ReadLine();

            StringBuilder Line = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo Key;
                try
                {
                    Key = ReadPromptKey();
                }
                catch (InvalidOperationException)
                {
                    return Line.Length == 0 ? null : Line.ToString();
                }

                if (Key.Key == ConsoleKey.Enter || Key.KeyChar == '\r' || Key.KeyChar == '\n')
                {
                    Console.WriteLine();
                    return Line.ToString();
                }

                if (Key.KeyChar == '\b')
                {
                    if (Line.Length != 0)
                    {
                        Line.Length--;
                        Console.Write("\b \b");
                    }
                    continue;
                }

                if (Key.KeyChar >= ' ')
                {
                    Line.Append(Key.KeyChar);
                    Console.Write(Key.KeyChar);
                }
            }
        }

        private static bool HasQueuedKeyDown()
        {
            lock (PromptGate)
            {
                if (HasPendingPrompt)
                    return true;

                while (GeneralHelper.HostConsoleInput.TryTake(out HostInputEvent Event))
                {
                    if (!IsKeyDown(in Event))
                        continue;

                    PendingPrompt = Event;
                    HasPendingPrompt = true;
                    return true;
                }

                return false;
            }
        }

        private static ConsoleKeyInfo FinishPress(in HostInputEvent Down)
        {
            if (GeneralHelper.HostConsoleInput.TryPeek(out HostInputEvent Next) && IsReleaseOf(in Next, in Down) &&
                GeneralHelper.HostConsoleInput.TryTake(out HostInputEvent Taken) && !IsReleaseOf(in Taken, in Down) && IsKeyDown(in Taken))
            {
                lock (PromptGate)
                {
                    PendingPrompt = Taken;
                    HasPendingPrompt = true;
                }
            }

            return ToKeyInfo(in Down);
        }

        private static bool IsKeyDown(in HostInputEvent Event) => Event.Kind == HostInputKind.Key && Event.KeyDown;

        private static bool IsReleaseOf(in HostInputEvent Event, in HostInputEvent Down) =>
            Event.Kind == HostInputKind.Key && !Event.KeyDown && Event.VirtualKey == Down.VirtualKey && Event.Character == Down.Character;

        private static ConsoleKeyInfo ToKeyInfo(in HostInputEvent Event)
        {
            uint State = Event.ControlKeyState;
            return new ConsoleKeyInfo(Event.Character, (ConsoleKey)Event.VirtualKey,
                (State & HostInputEvent.ShiftPressed) != 0,
                (State & (HostInputEvent.LeftAltPressed | HostInputEvent.RightAltPressed)) != 0,
                (State & (HostInputEvent.LeftCtrlPressed | HostInputEvent.RightCtrlPressed)) != 0);
        }

        private static bool RequestDemand(bool Blocking, Task Seen)
        {
            if (Seen.IsCompleted)
                return false;

            Volatile.Write(ref DemandFor, Seen);
            int Wanted = Blocking ? DemandBlocking : DemandIfReady;
            int Current = Volatile.Read(ref Demand);
            while (Current < Wanted)
            {
                int Previous = Interlocked.CompareExchange(ref Demand, Wanted, Current);
                if (Previous == Current)
                {
                    if (Current == DemandNone)
                        DemandSignal.Release();
                    return true;
                }

                Current = Previous;
            }

            return true;
        }

        // Console.KeyAvailable throws on redirected input.
        private static bool WaitForDemand(bool CanCheck)
        {
            DemandSignal.Wait();
            int Level = Interlocked.Exchange(ref Demand, DemandNone);
            if (Volatile.Read(ref DemandFor).IsCompleted)
                return false;

            return Level == DemandBlocking || !CanCheck || Console.KeyAvailable;
        }

        private static void RestoreControlC(object Sender, EventArgs Args)
        {
            try
            {
                Console.TreatControlCAsInput = SavedControlCAsInput;
            }
            catch (IOException Ex)
            {
                LogError($"Host console Ctrl+C mode could not be restored: {Ex.Message}");
            }
        }

        private static bool IsForcedExit(ConsoleKeyInfo Key)
        {
            if (Key.KeyChar != (char)0x03)
            {
                ControlCPresses = 0;
                return false;
            }

            long Now = Environment.TickCount64;
            if (ControlCPresses == 0 || Now - FirstControlCTick > ForcedExitWindowMilliseconds)
            {
                ControlCPresses = 0;
                FirstControlCTick = Now;
            }

            return ++ControlCPresses >= ForcedExitPresses;
        }

        private static uint StateOf(ConsoleModifiers Modifiers)
        {
            uint State = 0;
            if ((Modifiers & ConsoleModifiers.Control) != 0)
                State |= HostInputEvent.LeftCtrlPressed;
            if ((Modifiers & ConsoleModifiers.Alt) != 0)
                State |= HostInputEvent.LeftAltPressed;
            if ((Modifiers & ConsoleModifiers.Shift) != 0)
                State |= HostInputEvent.ShiftPressed;

            return State;
        }

        private static void ReadKeys()
        {
            try
            {
                while (true)
                {
                    if (!WaitForDemand(CanCheck: true))
                        continue;

                    ConsoleKeyInfo Key = Console.ReadKey(true);
                    if (IsForcedExit(Key))
                    {
                        Console.ResetColor();
                        Environment.Exit(0);
                    }

                    GeneralHelper.HostConsoleInput.PostKeyPress((ushort)Key.Key, Key.KeyChar, StateOf(Key.Modifiers));
                }
            }
            catch (Exception Ex) when (Ex is InvalidOperationException || Ex is IOException)
            {
                LogError($"Host console input stopped: {Ex.Message}");
            }

            GeneralHelper.HostConsoleInput.End();
        }

        private static void ReadLines()
        {
            try
            {
                while (true)
                {
                    if (!WaitForDemand(CanCheck: false))
                        continue;

                    string Line = Console.In.ReadLine();
                    if (Line == null)
                        break;

                    foreach (char Character in Line)
                        GeneralHelper.HostConsoleInput.PostKeyPress(0, Character, 0);

                    GeneralHelper.HostConsoleInput.PostKeyPress(VkReturn, '\r', 0);
                }
            }
            catch (IOException Ex)
            {
                LogError($"Host console input stopped: {Ex.Message}");
            }

            GeneralHelper.HostConsoleInput.End();
        }

        // DECCKM: CSI ? 1 h/l.
        private void TrackCursorKeys(ReadOnlySpan<byte> Data)
        {
            lock (TrackGate)
            {
                for (int i = 0; i < Data.Length; i++)
                {
                    if (OutputState == OutputParse.Ground)
                    {
                        int Escape = Data.Slice(i).IndexOf((byte)0x1B);
                        if (Escape < 0)
                            return;

                        i += Escape;
                        OutputState = OutputParse.Escape;
                        continue;
                    }

                    byte Value = Data[i];
                    switch (OutputState)
                    {
                        case OutputParse.Escape:
                            OutputState = Value == (byte)'[' ? OutputParse.CsiStart : Value == 0x1B ? OutputParse.Escape : OutputParse.Ground;
                            break;

                        case OutputParse.CsiStart:
                            OutputParameter = 0;
                            OutputParameterHasOne = false;
                            OutputState = Value == (byte)'?' ? OutputParse.PrivateParameters : Value == 0x1B ? OutputParse.Escape : OutputParse.Ground;
                            break;

                        case OutputParse.PrivateParameters:
                            if (Value >= (byte)'0' && Value <= (byte)'9')
                            {
                                OutputParameter = Math.Min(OutputParameter * 10 + (Value - '0'), 100000);
                            }
                            else if (Value == (byte)';')
                            {
                                OutputParameterHasOne |= OutputParameter == 1;
                                OutputParameter = 0;
                            }
                            else
                            {
                                if ((Value == (byte)'h' || Value == (byte)'l') && (OutputParameterHasOne || OutputParameter == 1))
                                    CursorKeysApplicationMode = Value == (byte)'h';

                                OutputState = Value == 0x1B ? OutputParse.Escape : OutputParse.Ground;
                            }
                            break;
                    }
                }
            }
        }

        private static void ReadHostWindow(ushort BufferWidth, ushort BufferHeight, out ushort Left, out ushort Top, out ushort Width, out ushort Height,
            out ushort LargestWidth, out ushort LargestHeight)
        {
            Left = 0;
            Top = 0;
            Width = BufferWidth;
            Height = BufferHeight;
            LargestWidth = BufferWidth;
            LargestHeight = BufferHeight;

            if (!HostConsoleUsable)
                return;

            try
            {
                int HostLeft = Math.Clamp(Console.WindowLeft, 0, BufferWidth - 1);
                int HostTop = Math.Clamp(Console.WindowTop, 0, BufferHeight - 1);
                int HostWidth = Math.Clamp(Console.WindowWidth, 1, BufferWidth - HostLeft);
                int HostHeight = Math.Clamp(Console.WindowHeight, 1, BufferHeight - HostTop);
                int HostLargestWidth = Math.Clamp(Console.LargestWindowWidth, 1, ushort.MaxValue);
                int HostLargestHeight = Math.Clamp(Console.LargestWindowHeight, 1, ushort.MaxValue);

                Left = (ushort)HostLeft;
                Top = (ushort)HostTop;
                Width = (ushort)HostWidth;
                Height = (ushort)HostHeight;
                LargestWidth = (ushort)HostLargestWidth;
                LargestHeight = (ushort)HostLargestHeight;
            }
            catch (Exception Error) when (Error is IOException || Error is PlatformNotSupportedException)
            {
            }
        }

        private static void ReadHostGeometry(out ushort Width, out ushort Height, out ushort CursorX, out ushort CursorY)
        {
            Width = DefaultBufferWidth;
            Height = DefaultBufferHeight;
            CursorX = 0;
            CursorY = 0;

            if (!HostConsoleUsable)
                return;

            try
            {
                Width = (ushort)Math.Max(1, Console.BufferWidth);
                Height = (ushort)Math.Max(1, Console.BufferHeight);
                CursorX = (ushort)Math.Max(0, Console.CursorLeft);
                CursorY = (ushort)Math.Max(0, Console.CursorTop);
            }
            catch (IOException)
            {
            }
        }

        private static void MoveHostCursor(int X, int Y)
        {
            if (!HostConsoleUsable)
                return;

            try
            {
                Console.SetCursorPosition(Math.Clamp(X, 0, Console.BufferWidth - 1), Math.Clamp(Y, 0, Console.BufferHeight - 1));
            }
            catch (IOException)
            {
            }
        }

        private void WriteRepeated(char Element, int Count, GuestConsoleOutputMode Mode)
        {
            Encoding Output = Encoding;
            Span<char> Single = stackalloc char[1] { Element };
            Span<byte> Encoded = stackalloc byte[Output.GetMaxByteCount(1)];
            int Length = Output.GetBytes(Single, Encoded);
            int Chunk = Math.Max(1, RepeatChunkBytes / Math.Max(Length, 1));

            byte[] Buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(Chunk * Length);
            try
            {
                for (int i = 0; i < Chunk; i++)
                    Encoded.Slice(0, Length).CopyTo(Buffer.AsSpan(i * Length));

                for (int Left = Count; Left > 0; Left -= Chunk)
                    GeneralHelper.ConsoleWrite(Buffer.AsSpan(0, Math.Min(Left, Chunk) * Length), Mode);
            }
            finally
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        private static unsafe bool IsHostNullDevice(HostStreamKind Stream)
        {
            (int StdHandle, int Descriptor) = Stream switch
            {
                HostStreamKind.Input => (NativeWinImports.StdInputHandle, 0),
                HostStreamKind.Error => (NativeWinImports.StdErrorHandle, 2),
                _ => (NativeWinImports.StdOutputHandle, 1),
            };

            if (GeneralHelper.IsWindows)
            {
                uint* Information = stackalloc uint[2];
                ulong* IoStatus = stackalloc ulong[2];
                IntPtr Handle = NativeWinImports.GetStdHandle(StdHandle);
                return NativeWinImports.NtQueryVolumeInformationFile(Handle, IoStatus, Information, sizeof(uint) * 2, (int)NtQueryVolumeInformationFile.FileFsDeviceInformation) >= 0 && Information[0] == NtQueryVolumeInformationFile.FILE_DEVICE_NULL;
            }

            const int AtEmptyPath = 0x1000;
            const uint StatxType = 0x1;
            const ushort FileTypeMask = 0xF000, CharacterDevice = 0x2000;
            byte* Buffer = stackalloc byte[256];
            if (!GeneralHelper.IO.TryStatx(Descriptor, string.Empty, AtEmptyPath, StatxType, Buffer))
                return false;

            // Linux: /dev/null is character device 1:3.
            return (*(ushort*)(Buffer + 0x1C) & FileTypeMask) == CharacterDevice && *(uint*)(Buffer + 0x80) == 1 && *(uint*)(Buffer + 0x84) == 3;
        }
    }
}
