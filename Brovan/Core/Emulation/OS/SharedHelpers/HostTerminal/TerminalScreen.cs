using System;
using System.Text;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public sealed class TerminalScreen
    {
        public const int DefaultColor = -1;
        public const int RgbColor = 0x1000000;

        public const byte FlagBold = 0x01;
        public const byte FlagFaint = 0x02;
        public const byte FlagItalic = 0x04;
        public const byte FlagUnderline = 0x08;
        public const byte FlagInverse = 0x10;
        public const byte FlagHidden = 0x20;
        public const byte FlagStrike = 0x40;
        public const byte FlagWideTail = 0x80;

        public const int SnapshotHeaderInts = 8;
        public const int SnapshotCellInts = 3;
        public const int SnapshotCursorVisible = 1;
        public const int SnapshotAlternate = 2;
        public const int SnapshotBusy = 0;

        public const int MaxColumns = 500;
        public const int MaxRows = 300;

        private const uint EnableProcessedOutput = 0x0001;
        private const uint EnableWrapAtEolOutput = 0x0002;
        private const uint EnableVirtualTerminalProcessing = 0x0004;
        private const uint DisableNewlineAutoReturn = 0x0008;

        private const ushort CommonLvbReverseVideo = 0x4000;
        private const ushort CommonLvbUnderscore = 0x8000;
        private const ushort DefaultAttributes = 0x0007;

        private const int MaxParameters = 16;
        private const int MaxParameterValue = 65535;
        private const int MaxReplyCharacters = 1024;
        private const int WriteSliceBytes = 4096;
        private const int TabWidth = 8;
        private const int Replacement = 0xFFFD;

        // conhost uses CP437 glyphs for unprocessed C0 controls.
        private const string ControlGlyphs = " ☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼";
        private const string LineDrawing = " ◆▒␉␌␍␊°±␤␋┘┐┌└┼⎺⎻─⎼⎽├┤┴┬│≤≥π≠£·";

        private struct Cell
        {
            public int Rune;
            public int Foreground;
            public int Background;
            public byte Flags;
        }

        private struct Pen
        {
            public int Foreground;
            public int Background;
            public byte Flags;
        }

        private enum ParseState
        {
            Ground,
            Escape,
            EscapeIntermediate,
            Csi,
            CsiIgnore,
            ControlString,
            ControlStringEscape
        }

        private readonly object Sync = new object();
        private readonly int[] Parameters = new int[MaxParameters];
        private readonly StringBuilder Replies = new StringBuilder();

        private int Columns;
        private int Rows;
        private Cell[][] Main;
        private Cell[][] Alternate;
        private bool AlternateActive;
        private bool[] TabStops;

        private Cell[][] History;
        private int HistoryStart;
        private int HistoryCount;

        private int CursorX;
        private int CursorY;
        private bool PendingWrap;
        private Pen Current;
        private int ScrollTop;
        private int ScrollBottom;
        private bool AutoWrap = true;
        private bool OriginMode;
        private bool InsertMode;
        private bool CursorShown = true;
        private bool CursorKeys;
        private bool LineDrawingSet;
        private uint CursorHeight = 25;
        private int LastPrinted = ' ';

        private int SavedX;
        private int SavedY;
        private Pen SavedPen;
        private bool SavedOriginMode;
        private bool SavedLineDrawing;

        private ParseState State;
        private int ParameterCount;
        private char PrivateMarker;
        private char Intermediate;
        private int Utf8Value;
        private int Utf8Remaining;
        private bool Dirty;
        private bool Announced;

        private long PendingSize;
        private bool Resized;

        public TerminalScreen(int Columns, int Rows)
        {
            Current = DefaultPen;
            SavedPen = DefaultPen;
            History = new Cell[Math.Max(Settings.MemoryBudget.TerminalScrollbackLines, 0)][];
            Allocate(Math.Clamp(Columns, 1, MaxColumns), Math.Clamp(Rows, 1, MaxRows));
        }

        private static Pen DefaultPen => new Pen { Foreground = DefaultColor, Background = DefaultColor };

        private Cell[][] Screen => AlternateActive ? Alternate : Main;

        private Cell Blank => new Cell { Rune = ' ', Foreground = Current.Foreground, Background = Current.Background };

        public void Write(ReadOnlySpan<byte> Data, uint OutputMode)
        {
            while (!Data.IsEmpty)
            {
                ReadOnlySpan<byte> Slice = Data.Slice(0, Math.Min(Data.Length, WriteSliceBytes));
                Data = Data.Slice(Slice.Length);

                lock (Sync)
                {
                    ApplyPendingSize();
                    for (int i = 0; i < Slice.Length; i++)
                        Decode(Slice[i], OutputMode);

                    Dirty = true;
                }
            }
        }

        public bool TakeChange()
        {
            lock (Sync)
            {
                if (!Dirty || Announced)
                    return false;

                Announced = true;
                return true;
            }
        }

        public void RequestResize(int NewColumns, int NewRows)
        {
            long Packed = ((long)Math.Clamp(NewColumns, 1, MaxColumns) << 32) | (uint)Math.Clamp(NewRows, 1, MaxRows);
            Interlocked.Exchange(ref PendingSize, Packed);

            if (!Monitor.TryEnter(Sync))
                return;

            try
            {
                ApplyPendingSize();
            }
            finally
            {
                Monitor.Exit(Sync);
            }
        }

        public bool TakeResize(out ushort NewColumns, out ushort NewRows)
        {
            lock (Sync)
            {
                NewColumns = (ushort)Columns;
                NewRows = (ushort)Rows;
                bool Value = Resized;
                Resized = false;
                return Value;
            }
        }

        public TerminalGeometry Geometry
        {
            get
            {
                lock (Sync)
                {
                    ApplyPendingSize();
                    return new TerminalGeometry
                    {
                        BufferWidth = (ushort)Columns,
                        BufferHeight = (ushort)Rows,
                        CursorX = (ushort)CursorX,
                        CursorY = (ushort)CursorY,
                        WindowWidth = (ushort)Columns,
                        WindowHeight = (ushort)Rows,
                        LargestWidth = (ushort)Columns,
                        LargestHeight = (ushort)Rows,
                    };
                }
            }
        }

        public void MoveCursor(int X, int Y)
        {
            lock (Sync)
            {
                CursorX = Math.Clamp(X, 0, Columns - 1);
                CursorY = Math.Clamp(Y, 0, Rows - 1);
                PendingWrap = false;
                Dirty = true;
            }
        }

        // NT: character fills keep each cell's attributes.
        public int Fill(int X, int Y, char Element, int Count)
        {
            lock (Sync)
            {
                if (X < 0 || Y < 0 || X >= Columns || Y >= Rows || Count <= 0)
                    return 0;

                int Cells = (int)Math.Min((long)(Rows - Y) * Columns - X, Count);
                Cell[][] Target = Screen;
                for (int i = 0; i < Cells; i++)
                {
                    int Index = X + i;
                    ref Cell Entry = ref Target[Y + Index / Columns][Index % Columns];
                    Entry.Rune = Element;
                    Entry.Flags &= unchecked((byte)~FlagWideTail);
                }

                Dirty = true;
                return Cells;
            }
        }

        public ushort Attributes
        {
            get
            {
                lock (Sync)
                {
                    int Foreground = Current.Foreground is >= 0 and < 16 ? Current.Foreground : DefaultAttributes;
                    int Background = Current.Background is >= 0 and < 16 ? Current.Background : 0;
                    ushort Value = (ushort)(SwapRedBlue(Foreground) | (SwapRedBlue(Background) << 4));
                    if ((Current.Flags & FlagInverse) != 0)
                        Value |= CommonLvbReverseVideo;
                    if ((Current.Flags & FlagUnderline) != 0)
                        Value |= CommonLvbUnderscore;

                    return Value;
                }
            }

            set
            {
                lock (Sync)
                {
                    int Foreground = SwapRedBlue(value & 0xF);
                    int Background = SwapRedBlue((value >> 4) & 0xF);
                    Current.Foreground = Foreground == DefaultAttributes ? DefaultColor : Foreground;
                    Current.Background = Background == 0 ? DefaultColor : Background;
                    Current.Flags = (byte)(Current.Flags & ~(FlagInverse | FlagUnderline));
                    if ((value & CommonLvbReverseVideo) != 0)
                        Current.Flags |= FlagInverse;
                    if ((value & CommonLvbUnderscore) != 0)
                        Current.Flags |= FlagUnderline;
                }
            }
        }

        public uint CursorSize
        {
            get
            {
                lock (Sync)
                    return CursorHeight;
            }

            set
            {
                lock (Sync)
                    CursorHeight = value;
            }
        }

        public bool CursorVisible
        {
            get
            {
                lock (Sync)
                    return CursorShown;
            }

            set
            {
                lock (Sync)
                {
                    CursorShown = value;
                    Dirty = true;
                }
            }
        }

        public bool CursorKeysApplication
        {
            get
            {
                lock (Sync)
                    return CursorKeys;
            }
        }

        public string TakeReplies()
        {
            lock (Sync)
            {
                if (Replies.Length == 0)
                    return null;

                string Value = Replies.ToString();
                Replies.Clear();
                return Value;
            }
        }

        public static int SnapshotInts(int Columns, int Rows) => SnapshotHeaderInts + Columns * Rows * SnapshotCellInts;

        public int Snapshot(Span<int> Destination, int ScrollBack)
        {
            if (!Monitor.TryEnter(Sync))
                return SnapshotBusy;

            try
            {
                ApplyPendingSize();
                int Needed = SnapshotInts(Columns, Rows);
                if (Destination.Length < Needed)
                    return -Needed;

                int Back = AlternateActive ? 0 : Math.Clamp(ScrollBack, 0, HistoryCount);
                Destination[0] = Columns;
                Destination[1] = Rows;
                Destination[2] = CursorX;
                Destination[3] = CursorY;
                Destination[4] = (CursorShown ? SnapshotCursorVisible : 0) | (AlternateActive ? SnapshotAlternate : 0);
                Destination[5] = HistoryCount;
                Destination[6] = Back;
                Destination[7] = 0;

                Cell[][] Live = Screen;
                int At = SnapshotHeaderInts;
                for (int Row = 0; Row < Rows; Row++)
                {
                    int Line = Row - Back;
                    Cell[] Source = Line < 0 ? History[(HistoryStart + HistoryCount + Line) % History.Length] : Live[Line];
                    int Width = Math.Min(Source.Length, Columns);

                    for (int Column = 0; Column < Columns; Column++)
                    {
                        Cell Entry = Column < Width ? Source[Column] : new Cell { Rune = ' ', Foreground = DefaultColor, Background = DefaultColor };
                        Destination[At++] = (Entry.Rune & 0xFFFFFF) | (Entry.Flags << 24);
                        Destination[At++] = Entry.Foreground;
                        Destination[At++] = Entry.Background;
                    }
                }

                Dirty = false;
                Announced = false;
                return Needed;
            }
            finally
            {
                Monitor.Exit(Sync);
            }
        }

        private void ApplyPendingSize()
        {
            long Packed = Interlocked.Exchange(ref PendingSize, 0);
            if (Packed == 0)
                return;

            int NewColumns = (int)(Packed >> 32);
            int NewRows = (int)(uint)Packed;
            if (NewColumns == Columns && NewRows == Rows)
                return;

            int ActiveShift = Math.Max(CursorY - NewRows + 1, 0);
            int MainShift = AlternateActive ? Math.Max(SavedY - NewRows + 1, 0) : ActiveShift;
            for (int Row = 0; Row < MainShift; Row++)
                PushHistory(Main[Row]);

            int OldRows = Rows;
            int Pulled = AlternateActive ? 0 : Math.Min(HistoryCount, Math.Max(NewRows - OldRows, 0));
            Cell[][] OldMain = Main;
            Cell[][] OldAlternate = Alternate;
            Allocate(NewColumns, NewRows);
            for (int Row = 0; Row < Pulled; Row++)
            {
                Cell[] Line = History[(HistoryStart + HistoryCount - Pulled + Row) % History.Length];
                Array.Copy(Line, Main[Row], Math.Min(Line.Length, Columns));
            }

            HistoryCount -= Pulled;
            CopyRows(OldMain, MainShift, Main, Pulled);
            CopyRows(OldAlternate, AlternateActive ? ActiveShift : 0, Alternate, 0);

            CursorY = Math.Clamp(CursorY - ActiveShift + Pulled, 0, Rows - 1);
            CursorX = Math.Clamp(CursorX, 0, Columns - 1);
            SavedX = Math.Clamp(SavedX, 0, Columns - 1);
            SavedY = Math.Clamp(SavedY - MainShift + Pulled, 0, Rows - 1);
            PendingWrap = false;
            Dirty = true;
            Resized = true;
        }

        private void Allocate(int NewColumns, int NewRows)
        {
            Columns = NewColumns;
            Rows = NewRows;
            Main = BlankLines(Rows);
            Alternate = BlankLines(Rows);
            TabStops = new bool[Columns];
            for (int Column = TabWidth; Column < Columns; Column += TabWidth)
                TabStops[Column] = true;

            ScrollTop = 0;
            ScrollBottom = Rows - 1;
        }

        private Cell[][] BlankLines(int Count)
        {
            Cell[][] Lines = new Cell[Count][];
            for (int Row = 0; Row < Count; Row++)
            {
                Lines[Row] = new Cell[Columns];
                Lines[Row].AsSpan().Fill(new Cell { Rune = ' ', Foreground = DefaultColor, Background = DefaultColor });
            }

            return Lines;
        }

        private void CopyRows(Cell[][] Source, int FirstRow, Cell[][] Target, int TargetRow)
        {
            for (int Row = TargetRow; Row < Rows && Row - TargetRow + FirstRow < Source.Length; Row++)
            {
                Cell[] Line = Source[Row - TargetRow + FirstRow];
                Array.Copy(Line, Target[Row], Math.Min(Line.Length, Columns));
            }
        }

        private Cell[] PushHistory(Cell[] Line)
        {
            if (History.Length == 0)
                return Line;

            int Slot;
            if (HistoryCount < History.Length)
            {
                Slot = (HistoryStart + HistoryCount) % History.Length;
                HistoryCount++;
            }
            else
            {
                Slot = HistoryStart;
                HistoryStart = (HistoryStart + 1) % History.Length;
            }

            Cell[] Recycled = History[Slot];
            History[Slot] = Line;
            return Recycled != null && Recycled.Length == Columns ? Recycled : new Cell[Columns];
        }

        private void Decode(byte Value, uint OutputMode)
        {
            if (Utf8Remaining != 0)
            {
                if ((Value & 0xC0) == 0x80)
                {
                    Utf8Value = (Utf8Value << 6) | (Value & 0x3F);
                    if (--Utf8Remaining == 0)
                        Feed(Utf8Value is > 0x10FFFF or (>= 0xD800 and <= 0xDFFF) ? Replacement : Utf8Value, OutputMode);
                    return;
                }

                Utf8Remaining = 0;
                Feed(Replacement, OutputMode);
            }

            if (Value < 0x80)
                Feed(Value, OutputMode);
            else if (Value >= 0xC2 && Value <= 0xDF)
                StartSequence(Value & 0x1F, 1);
            else if (Value >= 0xE0 && Value <= 0xEF)
                StartSequence(Value & 0x0F, 2);
            else if (Value >= 0xF0 && Value <= 0xF4)
                StartSequence(Value & 0x07, 3);
            else
                Feed(Replacement, OutputMode);
        }

        private void StartSequence(int Bits, int Remaining)
        {
            Utf8Value = Bits;
            Utf8Remaining = Remaining;
        }

        private void Feed(int Character, uint OutputMode)
        {
            switch (State)
            {
                case ParseState.Ground:
                    if (Character < 0x20 || Character == 0x7F)
                        Control(Character, OutputMode);
                    else
                        Print(Character, OutputMode);
                    return;

                case ParseState.Escape:
                    EscapeDispatch(Character, OutputMode);
                    return;

                case ParseState.EscapeIntermediate:
                    if (Character >= 0x20 && Character <= 0x2F)
                        return;

                    if (Intermediate == '(')
                        LineDrawingSet = Character == '0';

                    State = ParseState.Ground;
                    return;

                case ParseState.Csi:
                    CsiCharacter(Character, OutputMode);
                    return;

                case ParseState.CsiIgnore:
                    if (Character >= 0x40 && Character <= 0x7E)
                        State = ParseState.Ground;
                    else if (Character == 0x1B)
                        State = ParseState.Escape;
                    return;

                case ParseState.ControlString:
                    if (Character == 0x07)
                        State = ParseState.Ground;
                    else if (Character == 0x1B)
                        State = ParseState.ControlStringEscape;
                    return;

                case ParseState.ControlStringEscape:
                    State = ParseState.Ground;
                    if (Character != '\\')
                        EscapeDispatch(Character, OutputMode);
                    return;
            }
        }

        private void Control(int Character, uint OutputMode)
        {
            if ((OutputMode & EnableProcessedOutput) == 0)
            {
                Print(Character == 0x7F ? '⌂' : ControlGlyphs[Character], OutputMode);
                return;
            }

            switch (Character)
            {
                case 0x00:
                case 0x07:
                    return;

                case 0x08:
                    if (CursorX > 0)
                        CursorX--;
                    PendingWrap = false;
                    return;

                case 0x09:
                    TabForward(1);
                    return;

                case 0x0A:
                case 0x0B:
                case 0x0C:
                    LineFeed();
                    if ((OutputMode & DisableNewlineAutoReturn) == 0)
                        CursorX = 0;
                    return;

                case 0x0D:
                    CursorX = 0;
                    PendingWrap = false;
                    return;

                case 0x0E:
                case 0x0F:
                    return;

                case 0x1B:
                    if ((OutputMode & EnableVirtualTerminalProcessing) == 0)
                    {
                        Print(ControlGlyphs[Character], OutputMode);
                        return;
                    }

                    State = ParseState.Escape;
                    return;

                default:
                    Print(Character == 0x7F ? '⌂' : ControlGlyphs[Character], OutputMode);
                    return;
            }
        }

        private void EscapeDispatch(int Character, uint OutputMode)
        {
            State = ParseState.Ground;
            switch (Character)
            {
                case '[':
                    ParameterCount = 0;
                    PrivateMarker = '\0';
                    Intermediate = '\0';
                    Array.Clear(Parameters);
                    State = ParseState.Csi;
                    return;

                case ']':
                case 'P':
                case 'X':
                case '^':
                case '_':
                    State = ParseState.ControlString;
                    return;

                case '7':
                    SaveCursor();
                    return;

                case '8':
                    RestoreCursor();
                    return;

                case 'D':
                    LineFeed();
                    return;

                case 'E':
                    CursorX = 0;
                    LineFeed();
                    return;

                case 'M':
                    ReverseIndex();
                    return;

                case 'H':
                    TabStops[CursorX] = true;
                    return;

                case 'c':
                    Reset();
                    return;

                case 0x1B:
                    State = ParseState.Escape;
                    return;
            }

            if (Character >= 0x20 && Character <= 0x2F)
            {
                Intermediate = (char)Character;
                State = ParseState.EscapeIntermediate;
            }
        }

        private void CsiCharacter(int Character, uint OutputMode)
        {
            if (Character >= '0' && Character <= '9')
            {
                if (ParameterCount == 0)
                    ParameterCount = 1;

                ref int Value = ref Parameters[ParameterCount - 1];
                Value = Math.Min(Value * 10 + (Character - '0'), MaxParameterValue);
                return;
            }

            if (Character == ';' || Character == ':')
            {
                if (ParameterCount == 0)
                    ParameterCount = 1;

                if (ParameterCount == MaxParameters)
                {
                    State = ParseState.CsiIgnore;
                    return;
                }

                ParameterCount++;
                return;
            }

            if (Character >= 0x3C && Character <= 0x3F)
            {
                if (ParameterCount != 0 || PrivateMarker != '\0')
                    State = ParseState.CsiIgnore;
                else
                    PrivateMarker = (char)Character;
                return;
            }

            if (Character >= 0x20 && Character <= 0x2F)
            {
                Intermediate = (char)Character;
                return;
            }

            if (Character >= 0x40 && Character <= 0x7E)
            {
                State = ParseState.Ground;
                CsiDispatch((char)Character, OutputMode);
                return;
            }

            if (Character == 0x1B)
            {
                State = ParseState.Escape;
                return;
            }

            if (Character == 0x18 || Character == 0x1A)
            {
                State = ParseState.Ground;
                return;
            }

            if (Character < 0x20)
                Control(Character, OutputMode);
            else
                State = ParseState.CsiIgnore;
        }

        private int Parameter(int Index, int Default)
        {
            int Value = Index < ParameterCount ? Parameters[Index] : 0;
            return Value == 0 ? Default : Value;
        }

        private void CsiDispatch(char Final, uint OutputMode)
        {
            if (Intermediate != '\0')
            {
                if (Intermediate == '!' && Final == 'p')
                    SoftReset();
                return;
            }

            if (PrivateMarker == '?')
            {
                if (Final == 'h' || Final == 'l')
                    SetPrivateModes(Final == 'h');
                return;
            }

            if (PrivateMarker != '\0')
                return;

            int Count = Parameter(0, 1);
            switch (Final)
            {
                case '@':
                    InsertCells(Count);
                    break;
                case 'A':
                    CursorY = Math.Max(CursorY - Count, CursorY >= ScrollTop ? ScrollTop : 0);
                    break;
                case 'B':
                    CursorY = Math.Min(CursorY + Count, CursorY <= ScrollBottom ? ScrollBottom : Rows - 1);
                    break;
                case 'C':
                case 'a':
                    CursorX = Math.Min(CursorX + Count, Columns - 1);
                    break;
                case 'D':
                    CursorX = Math.Max(CursorX - Count, 0);
                    break;
                case 'E':
                    CursorY = Math.Min(CursorY + Count, CursorY <= ScrollBottom ? ScrollBottom : Rows - 1);
                    CursorX = 0;
                    break;
                case 'F':
                    CursorY = Math.Max(CursorY - Count, CursorY >= ScrollTop ? ScrollTop : 0);
                    CursorX = 0;
                    break;
                case 'G':
                case '`':
                    CursorX = Math.Clamp(Count - 1, 0, Columns - 1);
                    break;
                case 'H':
                case 'f':
                    SetPosition(Parameter(1, 1) - 1, Parameter(0, 1) - 1);
                    break;
                case 'I':
                    TabForward(Count);
                    break;
                case 'Z':
                    TabBackward(Count);
                    break;
                case 'J':
                    EraseDisplay(Parameter(0, 0));
                    break;
                case 'K':
                    EraseLine(Parameter(0, 0));
                    break;
                case 'L':
                    if (CursorY >= ScrollTop && CursorY <= ScrollBottom)
                        ScrollDown(CursorY, ScrollBottom, Count);
                    CursorX = 0;
                    break;
                case 'M':
                    if (CursorY >= ScrollTop && CursorY <= ScrollBottom)
                        ScrollUp(CursorY, ScrollBottom, Count);
                    CursorX = 0;
                    break;
                case 'P':
                    DeleteCells(Count);
                    break;
                case 'S':
                    ScrollUp(ScrollTop, ScrollBottom, Count);
                    break;
                case 'T':
                    ScrollDown(ScrollTop, ScrollBottom, Count);
                    break;
                case 'X':
                    ClearCells(Screen[CursorY], CursorX, Math.Min(Count, Columns - CursorX));
                    break;
                case 'b':
                    Repeat(Count, OutputMode);
                    break;
                case 'd':
                    SetPosition(CursorX, Count - 1);
                    break;
                case 'e':
                    CursorY = Math.Min(CursorY + Count, Rows - 1);
                    break;
                case 'g':
                    if (Parameter(0, 0) == 0)
                        TabStops[CursorX] = false;
                    else if (Parameter(0, 0) == 3)
                        Array.Clear(TabStops);
                    break;
                case 'h':
                case 'l':
                    if (Parameter(0, 0) == 4)
                        InsertMode = Final == 'h';
                    break;
                case 'm':
                    SelectGraphicRendition();
                    break;
                case 'n':
                    ReportStatus(Parameter(0, 0));
                    break;
                case 'r':
                    SetScrollRegion(Parameter(0, 1) - 1, Parameter(1, Rows) - 1);
                    break;
                case 's':
                    if (ParameterCount == 0)
                        SaveCursor();
                    break;
                case 'u':
                    RestoreCursor();
                    break;
            }

            if (Final != 'm' && Final != 'n' && Final != 'b')
                PendingWrap = false;
        }

        // conhost does not cap REP. Skip full lines once screen and history are filled.
        private void Repeat(int Count, uint OutputMode)
        {
            int Width = CellWidth(LastPrinted);
            if (Width == 0)
                return;

            bool Wrap = AutoWrap && (OutputMode & EnableWrapAtEolOutput) != 0;
            int PerLine = Width == 2 && Columns >= 2 ? Columns / 2 : Columns;
            if (!Wrap)
            {
                Count = Math.Min(Count, PerLine);
            }
            else
            {
                bool KeepsHistory = ScrollTop == 0 && !AlternateActive;
                long Lines = Rows + (KeepsHistory ? History.Length : 0) + 2;
                long Limit = Lines * PerLine;
                if (Count > Limit)
                    Count -= (int)((Count - Limit) / PerLine * PerLine);
            }

            for (int i = 0; i < Count; i++)
                Print(LastPrinted, OutputMode);
        }

        private void SetPrivateModes(bool Enabled)
        {
            for (int i = 0; i < Math.Max(ParameterCount, 1); i++)
            {
                switch (Parameters[i])
                {
                    case 1:
                        CursorKeys = Enabled;
                        break;
                    case 6:
                        OriginMode = Enabled;
                        SetPosition(0, 0);
                        break;
                    case 7:
                        AutoWrap = Enabled;
                        break;
                    case 25:
                        CursorShown = Enabled;
                        break;
                    case 47:
                    case 1047:
                        SwitchScreen(Enabled, false);
                        break;
                    case 1049:
                        SwitchScreen(Enabled, true);
                        break;
                }
            }
        }

        private void SwitchScreen(bool UseAlternate, bool SaveAndClear)
        {
            if (UseAlternate == AlternateActive)
                return;

            if (UseAlternate && SaveAndClear)
                SaveCursor();

            AlternateActive = UseAlternate;
            if (UseAlternate && SaveAndClear)
                ClearRows(Alternate, 0, Rows - 1);

            if (!UseAlternate && SaveAndClear)
                RestoreCursor();

            ScrollTop = 0;
            ScrollBottom = Rows - 1;
        }

        private void SelectGraphicRendition()
        {
            if (ParameterCount == 0)
            {
                Current = DefaultPen;
                return;
            }

            for (int i = 0; i < ParameterCount; i++)
            {
                int Code = Parameters[i];
                switch (Code)
                {
                    case 0:
                        Current = DefaultPen;
                        break;
                    case 1:
                        Current.Flags |= FlagBold;
                        break;
                    case 2:
                        Current.Flags |= FlagFaint;
                        break;
                    case 3:
                        Current.Flags |= FlagItalic;
                        break;
                    case 4:
                    case 21:
                        Current.Flags |= FlagUnderline;
                        break;
                    case 7:
                        Current.Flags |= FlagInverse;
                        break;
                    case 8:
                        Current.Flags |= FlagHidden;
                        break;
                    case 9:
                        Current.Flags |= FlagStrike;
                        break;
                    case 22:
                        Current.Flags &= unchecked((byte)~(FlagBold | FlagFaint));
                        break;
                    case 23:
                        Current.Flags &= unchecked((byte)~FlagItalic);
                        break;
                    case 24:
                        Current.Flags &= unchecked((byte)~FlagUnderline);
                        break;
                    case 27:
                        Current.Flags &= unchecked((byte)~FlagInverse);
                        break;
                    case 28:
                        Current.Flags &= unchecked((byte)~FlagHidden);
                        break;
                    case 29:
                        Current.Flags &= unchecked((byte)~FlagStrike);
                        break;
                    case >= 30 and <= 37:
                        Current.Foreground = Code - 30;
                        break;
                    case 38:
                        Current.Foreground = ExtendedColor(ref i, Current.Foreground);
                        break;
                    case 39:
                        Current.Foreground = DefaultColor;
                        break;
                    case >= 40 and <= 47:
                        Current.Background = Code - 40;
                        break;
                    case 48:
                        Current.Background = ExtendedColor(ref i, Current.Background);
                        break;
                    case 49:
                        Current.Background = DefaultColor;
                        break;
                    case >= 90 and <= 97:
                        Current.Foreground = Code - 90 + 8;
                        break;
                    case >= 100 and <= 107:
                        Current.Background = Code - 100 + 8;
                        break;
                }
            }
        }

        private int ExtendedColor(ref int Index, int Unchanged)
        {
            if (Index + 1 >= ParameterCount)
                return Unchanged;

            int Kind = Parameters[++Index];
            if (Kind == 5 && Index + 1 < ParameterCount)
                return Math.Min(Parameters[++Index], 255);

            if (Kind == 2 && Index + 3 < ParameterCount)
            {
                int Red = Math.Min(Parameters[++Index], 255);
                int Green = Math.Min(Parameters[++Index], 255);
                int Blue = Math.Min(Parameters[++Index], 255);
                return RgbColor | (Red << 16) | (Green << 8) | Blue;
            }

            return Unchanged;
        }

        private void ReportStatus(int Kind)
        {
            if (Replies.Length >= MaxReplyCharacters)
                return;

            if (Kind == 5)
            {
                Replies.Append("\x1b[0n");
            }
            else if (Kind == 6)
            {
                int Row = OriginMode ? CursorY - ScrollTop : CursorY;
                Replies.Append("\x1b[").Append(Row + 1).Append(';').Append(CursorX + 1).Append('R');
            }
        }

        // conhost delays wrapping only in VT mode.
        private void Print(int Character, uint OutputMode)
        {
            if (LineDrawingSet && Character >= 0x5F && Character <= 0x7E)
                Character = LineDrawing[Character - 0x5F];

            int Width = CellWidth(Character);
            if (Width == 0)
                return;

            if (Width == 2 && Columns < 2)
                Width = 1;

            bool Wrap = AutoWrap && (OutputMode & EnableWrapAtEolOutput) != 0;
            if (PendingWrap)
            {
                PendingWrap = false;
                if (Wrap)
                {
                    CursorX = 0;
                    LineFeed();
                }
            }

            if (Width == 2 && CursorX == Columns - 1)
            {
                if (Wrap)
                {
                    PutCell(CursorX, ' ');
                    CursorX = 0;
                    LineFeed();
                }
                else
                {
                    Width = 1;
                    Character = ' ';
                }
            }

            if (InsertMode)
                InsertCells(Width);

            PutCell(CursorX, Character);
            if (Width == 2)
            {
                Screen[CursorY][CursorX + 1] = new Cell
                {
                    Rune = 0,
                    Foreground = Current.Foreground,
                    Background = Current.Background,
                    Flags = (byte)(Current.Flags | FlagWideTail)
                };
            }

            LastPrinted = Character;
            CursorX += Width;
            if (CursorX < Columns)
                return;

            if (Wrap && (OutputMode & EnableVirtualTerminalProcessing) == 0)
            {
                CursorX = 0;
                LineFeed();
                return;
            }

            CursorX = Columns - 1;
            PendingWrap = Wrap;
        }

        private void PutCell(int Column, int Character)
        {
            Cell[] Line = Screen[CursorY];
            if ((Line[Column].Flags & FlagWideTail) != 0 && Column > 0)
                Line[Column - 1].Rune = ' ';

            if (Column + 1 < Columns && (Line[Column + 1].Flags & FlagWideTail) != 0)
            {
                Line[Column + 1].Rune = ' ';
                Line[Column + 1].Flags &= unchecked((byte)~FlagWideTail);
            }

            Line[Column] = new Cell { Rune = Character, Foreground = Current.Foreground, Background = Current.Background, Flags = Current.Flags };
        }

        private static int CellWidth(int Character)
        {
            if ((Character >= 0x0300 && Character <= 0x036F) || (Character >= 0x200B && Character <= 0x200F) || (Character >= 0xFE00 && Character <= 0xFE0F))
                return 0;

            if ((Character >= 0x1100 && Character <= 0x115F) || (Character >= 0x2E80 && Character <= 0x303E) ||
                (Character >= 0x3041 && Character <= 0x33FF) || (Character >= 0x3400 && Character <= 0x4DBF) ||
                (Character >= 0x4E00 && Character <= 0x9FFF) || (Character >= 0xA000 && Character <= 0xA4CF) ||
                (Character >= 0xAC00 && Character <= 0xD7A3) || (Character >= 0xF900 && Character <= 0xFAFF) ||
                (Character >= 0xFE30 && Character <= 0xFE4F) || (Character >= 0xFF00 && Character <= 0xFF60) ||
                (Character >= 0xFFE0 && Character <= 0xFFE6) || (Character >= 0x1F300 && Character <= 0x1F64F) ||
                (Character >= 0x1F900 && Character <= 0x1F9FF) || (Character >= 0x20000 && Character <= 0x3FFFD))
                return 2;

            return 1;
        }

        private void LineFeed()
        {
            PendingWrap = false;
            if (CursorY == ScrollBottom)
                ScrollUp(ScrollTop, ScrollBottom, 1);
            else if (CursorY < Rows - 1)
                CursorY++;
        }

        private void ReverseIndex()
        {
            PendingWrap = false;
            if (CursorY == ScrollTop)
                ScrollDown(ScrollTop, ScrollBottom, 1);
            else if (CursorY > 0)
                CursorY--;
        }

        private void ScrollUp(int Top, int Bottom, int Count)
        {
            Count = Math.Clamp(Count, 0, Bottom - Top + 1);
            Cell[][] Target = Screen;
            bool KeepHistory = Top == 0 && !AlternateActive;
            for (int i = 0; i < Count; i++)
            {
                Cell[] Leaving = KeepHistory ? PushHistory(Target[Top]) : Target[Top];
                Array.Copy(Target, Top + 1, Target, Top, Bottom - Top);
                Target[Bottom] = Leaving;
                Leaving.AsSpan().Fill(Blank);
            }
        }

        private void ScrollDown(int Top, int Bottom, int Count)
        {
            Count = Math.Clamp(Count, 0, Bottom - Top + 1);
            Cell[][] Target = Screen;
            for (int i = 0; i < Count; i++)
            {
                Cell[] Leaving = Target[Bottom];
                Array.Copy(Target, Top, Target, Top + 1, Bottom - Top);
                Target[Top] = Leaving;
                Leaving.AsSpan().Fill(Blank);
            }
        }

        private void InsertCells(int Count)
        {
            Count = Math.Clamp(Count, 0, Columns - CursorX);
            Cell[] Line = Screen[CursorY];
            Array.Copy(Line, CursorX, Line, CursorX + Count, Columns - CursorX - Count);
            Line.AsSpan(CursorX, Count).Fill(Blank);
        }

        private void DeleteCells(int Count)
        {
            Count = Math.Clamp(Count, 0, Columns - CursorX);
            Cell[] Line = Screen[CursorY];
            Array.Copy(Line, CursorX + Count, Line, CursorX, Columns - CursorX - Count);
            Line.AsSpan(Columns - Count, Count).Fill(Blank);
        }

        private void ClearCells(Cell[] Line, int Start, int Count)
        {
            if (Count > 0)
                Line.AsSpan(Start, Count).Fill(Blank);
        }

        private void ClearRows(int First, int Last) => ClearRows(Screen, First, Last);

        private void ClearRows(Cell[][] Lines, int First, int Last)
        {
            for (int Row = First; Row <= Last; Row++)
                Lines[Row].AsSpan().Fill(Blank);
        }

        private void EraseDisplay(int Kind)
        {
            Cell[] Line = Screen[CursorY];
            switch (Kind)
            {
                case 0:
                    ClearCells(Line, CursorX, Columns - CursorX);
                    ClearRows(CursorY + 1, Rows - 1);
                    break;
                case 1:
                    ClearRows(0, CursorY - 1);
                    ClearCells(Line, 0, CursorX + 1);
                    break;
                case 2:
                    ClearRows(0, Rows - 1);
                    break;
                case 3:
                    HistoryStart = 0;
                    HistoryCount = 0;
                    break;
            }
        }

        private void EraseLine(int Kind)
        {
            Cell[] Line = Screen[CursorY];
            switch (Kind)
            {
                case 0:
                    ClearCells(Line, CursorX, Columns - CursorX);
                    break;
                case 1:
                    ClearCells(Line, 0, CursorX + 1);
                    break;
                case 2:
                    ClearCells(Line, 0, Columns);
                    break;
            }
        }

        private void SetPosition(int X, int Y)
        {
            int Top = OriginMode ? ScrollTop : 0;
            int Bottom = OriginMode ? ScrollBottom : Rows - 1;
            CursorX = Math.Clamp(X, 0, Columns - 1);
            CursorY = Math.Clamp(Y + Top, Top, Bottom);
        }

        private void SetScrollRegion(int Top, int Bottom)
        {
            Bottom = Math.Min(Bottom, Rows - 1);
            if (Top < 0 || Top >= Bottom)
                return;

            ScrollTop = Top;
            ScrollBottom = Bottom;
            SetPosition(0, 0);
        }

        private void TabForward(int Count)
        {
            for (int i = 0; i < Count && CursorX < Columns - 1; i++)
            {
                do
                    CursorX++;
                while (CursorX < Columns - 1 && !TabStops[CursorX]);
            }

            PendingWrap = false;
        }

        private void TabBackward(int Count)
        {
            for (int i = 0; i < Count && CursorX > 0; i++)
            {
                do
                    CursorX--;
                while (CursorX > 0 && !TabStops[CursorX]);
            }
        }

        private void SaveCursor()
        {
            SavedX = CursorX;
            SavedY = CursorY;
            SavedPen = Current;
            SavedOriginMode = OriginMode;
            SavedLineDrawing = LineDrawingSet;
        }

        private void RestoreCursor()
        {
            CursorX = Math.Clamp(SavedX, 0, Columns - 1);
            CursorY = Math.Clamp(SavedY, 0, Rows - 1);
            Current = SavedPen;
            OriginMode = SavedOriginMode;
            LineDrawingSet = SavedLineDrawing;
            PendingWrap = false;
        }

        // DECSTR keeps the screen contents.
        private void SoftReset()
        {
            CursorShown = true;
            CursorKeys = false;
            InsertMode = false;
            OriginMode = false;
            AutoWrap = true;
            LineDrawingSet = false;
            Current = DefaultPen;
            ScrollTop = 0;
            ScrollBottom = Rows - 1;
            SavedX = 0;
            SavedY = 0;
            SavedPen = DefaultPen;
        }

        private void Reset()
        {
            SoftReset();
            AlternateActive = false;
            ClearRows(Main, 0, Rows - 1);
            ClearRows(Alternate, 0, Rows - 1);
            HistoryStart = 0;
            HistoryCount = 0;
            CursorX = 0;
            CursorY = 0;
            PendingWrap = false;
            Array.Clear(TabStops);
            for (int Column = TabWidth; Column < Columns; Column += TabWidth)
                TabStops[Column] = true;
        }

        // Console colors use BGR bits. VT uses RGB.
        private static int SwapRedBlue(int Color) => (Color & 0xA) | ((Color & 1) << 2) | ((Color & 4) >> 2);
    }
}
