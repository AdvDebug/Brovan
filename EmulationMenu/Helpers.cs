using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using Brovan.Analysis;
using static Brovan.Variables;
using static Brovan.Core.Helpers.BinaryHelpers;
using System.Reflection;
using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.Utils;

namespace Brovan
{
    public class Helpers
    {
        private const int DebuggerCommandHistoryLimit = 128;
        private static readonly object DebuggerConsoleLock = new();

        private readonly struct DebuggerConsoleViewport
        {
            public DebuggerConsoleViewport(int top, int height)
            {
                Top = top;
                Height = height;
            }

            public int Top { get; }
            public int Height { get; }
            public int BottomExclusive => Top + Height;
        }

        public static string FormatWatchType(MemoryWatchType Type)
        {
            return Type switch
            {
                MemoryWatchType.Read => "read",
                MemoryWatchType.Write => "write",
                MemoryWatchType.Fetch => "fetch",
                _ => "access"
            };
        }

        public static bool TryGetInclusiveEnd(ulong Address, ulong Size, out ulong EndAddress)
        {
            EndAddress = Address;
            if (Size == 0)
                return false;

            ulong Delta = Size - 1;
            if (Address > ulong.MaxValue - Delta)
                return false;

            EndAddress = Address + Delta;
            return true;
        }

        public static bool TryFindMemoryRegion(ulong Address, out MemoryRegion Region)
        {
            Region = default;
            if (Emulator?._memory == null)
                return false;

            foreach (MemoryRegion Candidate in Emulator._memory)
            {
                if (Candidate.Size == 0)
                    continue;

                ulong RegionEnd = Candidate.BaseAddress + Candidate.Size;
                if (RegionEnd < Candidate.BaseAddress)
                    RegionEnd = ulong.MaxValue;

                if (Address >= Candidate.BaseAddress && Address < RegionEnd)
                {
                    Region = Candidate;
                    return true;
                }
            }

            return false;
        }

        public static ulong GetPageSize(ulong BaseAddress)
        {
            foreach (MemoryRegion Region in Emulator._memory)
            {
                if (Region.BaseAddress == BaseAddress)
                    return Region.Size;
            }
            return 0x1000;
        }

        public static bool Display(ulong Address, ulong SecondAddress, ulong IP)
        {
            ulong Size = GetPageSize(SecondAddress);
            bool InTargetRange = Address >= SecondAddress && Address <= SecondAddress + Size;
            bool InMainModule = Emulator?.WinHelper?.WinModules?.Count > 0 && IP >= MappedMainModuleBase && IP <= MappedMainModuleBase + Emulator.WinHelper.WinModules[0].SizeOfImage;
            return InTargetRange && (Variables.Debug || InMainModule);
        }

        public static bool InsideWinModule(ulong Address, WinModule Module)
        {
            if (Variables.Debug) return true;
            if (Address >= Module.MappedBase && Address <= Module.MappedBase + Module.SizeOfImage)
                return true;
            return false;
        }

        public static string GetAction(MemoryType Type)
        {
            return Type switch
            {
                MemoryType.UC_MEM_READ => "Reading from",
                MemoryType.UC_MEM_WRITE => "Writing to",
                _ => "Unknown action to the"
            };
        }

        internal static bool PrepareDebuggerResume()
        {
            RestoreDebuggerPausedThreadStates();
            return StepPastCurrentBreakpoint();
        }

        internal static void RestoreDebuggerPause()
        {
            RestoreDebuggerPausedThreadStates();
        }

        internal static void ArmCurrentBreakpointSkip()
        {
            ClearBreakpointSkip();

            if (Emulator == null)
                return;

            ulong CurrentIp = Emulator.ReadRegister(Emulator.IPRegister);
            if (!Breakpoints.Contains(CurrentIp))
                return;

            SkipBreakpointOnce = true;
            SkipBreakpointAddress = CurrentIp;
            SkipBreakpointThreadId = Emulator.CurrentThreadId;
        }

        internal static bool ShouldSkipBreakpoint(ulong Address)
        {
            if (!SkipBreakpointOnce)
                return false;

            int CurrentThreadId = Emulator?.CurrentThreadId ?? 0;
            if (CurrentThreadId != SkipBreakpointThreadId)
                return false;

            if (Address != SkipBreakpointAddress)
            {
                ClearBreakpointSkip();
                return false;
            }

            ClearBreakpointSkip();
            return true;
        }

        internal static void ClearBreakpointSkip()
        {
            SkipBreakpointOnce = false;
            SkipBreakpointAddress = 0;
            SkipBreakpointThreadId = 0;
        }

        internal static bool StepCurrentInstruction(bool SuppressBreakpoints)
        {
            if (Emulator == null)
                return false;

            ClearBreakpointSkip();
            ulong CurrentIp = Emulator.ReadRegister(Emulator.IPRegister);
            bool PreviousSuppression = BreakpointsSuppressed;
            BreakpointsSuppressed = PreviousSuppression || SuppressBreakpoints;

            try
            {
                bool Result = Emulator.StartEmulation(CurrentIp, 0, 0, 1, false);
                if (Emulator.CurrentThread != null)
                    Emulator.SaveContext(Emulator.CurrentThread);

                return Result;
            }
            finally
            {
                BreakpointsSuppressed = PreviousSuppression;
            }
        }

        internal static bool StepPastCurrentBreakpoint()
        {
            if (Emulator == null)
                return true;

            ClearBreakpointSkip();
            ulong CurrentIp = Emulator.ReadRegister(Emulator.IPRegister);
            if (!Breakpoints.Contains(CurrentIp))
                return true;

            return StepCurrentInstruction(true);
        }

        internal static bool TryDecodeInstructionAt(ulong Address, out X86Instruction Instruction, out string FormattedInstruction)
        {
            Instruction = default;
            FormattedInstruction = $"0x{Address:X}: <disassembly unavailable>";

            if (Disassembler == null || Emulator == null)
                return false;

            if (Emulator.Guest is GenericGuest Generic && !Generic.IsX86)
                return false;

            byte[]? Bytes = null;
            const uint MaxX86InstructionLength = 15;
            for (uint Length = MaxX86InstructionLength; Length > 0; Length--)
            {
                try
                {
                    Bytes = Emulator.ReadMemory(Address, Length);
                    break;
                }
                catch
                {
                    Bytes = null;
                }
            }

            if (Bytes == null || Bytes.Length == 0)
            {
                FormattedInstruction = $"0x{Address:X}: <failed to read instruction bytes>";
                return false;
            }

            X86Instruction[] Instructions;
            try
            {
                Instructions = Disassembler.DisassembleBinary(Bytes, Address, Binary, 1, true);
            }
            catch
            {
                FormattedInstruction = $"0x{Address:X}: <failed to decode instruction>";
                return false;
            }

            if (Instructions.Length == 0)
            {
                FormattedInstruction = $"0x{Address:X}: <failed to decode instruction>";
                return false;
            }

            Instruction = Instructions[0];
            FormattedInstruction = FormatInstructionForDebugger(Instruction);
            return true;
        }

        internal static string FormatInstructionForDebugger(X86Instruction Instruction)
        {
            string Text = Instruction.Mnemonic ?? string.Empty;
            if (!string.IsNullOrEmpty(Instruction.Operand))
                Text += " " + Instruction.Operand;

            return $"0x{Instruction.Address:X}: {Text}";
        }

        internal static void PrintStoppedInstruction(string Prefix, ulong Address)
        {
            TryDecodeInstructionAt(Address, out _, out string FormattedInstruction);
            PrintHighlight($"{Prefix} {FormattedInstruction}", true);
        }

        internal static void PrintCurrentInstruction(string Prefix)
        {
            if (Emulator == null)
                return;

            PrintStoppedInstruction(Prefix, Emulator.ReadRegister(Emulator.IPRegister));
        }

        internal static bool TryDecodeInstructionBlock(ulong Address, int MaxInstructions, out X86Instruction[] Instructions)
        {
            Instructions = Array.Empty<X86Instruction>();

            if (MaxInstructions <= 0 || Disassembler == null || Emulator == null)
                return false;

            if (Emulator.Guest is GenericGuest Generic && !Generic.IsX86)
                return false;

            byte[]? Bytes = null;
            int ReadLength = Math.Clamp(MaxInstructions * 15, 15, 192);
            for (int Length = ReadLength; Length >= 15; Length -= 15)
            {
                try
                {
                    Bytes = Emulator.ReadMemory(Address, (uint)Length);
                    break;
                }
                catch
                {
                    Bytes = null;
                }
            }

            if (Bytes == null || Bytes.Length == 0)
                return false;

            try
            {
                Instructions = Disassembler.DisassembleBinary(Bytes, Address, Binary, MaxInstructions, true);
                return Instructions.Length != 0;
            }
            catch
            {
                Instructions = Array.Empty<X86Instruction>();
                return false;
            }
        }

        private readonly struct DebuggerTextSegment
        {
            public readonly string Text;
            public readonly ConsoleColor? Foreground;
            public readonly ConsoleColor? Background;

            public DebuggerTextSegment(string Text, ConsoleColor? Foreground = null, ConsoleColor? Background = null)
            {
                this.Text = Text ?? string.Empty;
                this.Foreground = Foreground;
                this.Background = Background;
            }
        }

        private sealed class DebuggerDisplayLine
        {
            public readonly List<DebuggerTextSegment> Segments = new();

            public DebuggerDisplayLine Add(string Text, ConsoleColor? Foreground = null, ConsoleColor? Background = null)
            {
                if (!string.IsNullOrEmpty(Text))
                    Segments.Add(new DebuggerTextSegment(Text, Foreground, Background));

                return this;
            }
        }

        private readonly struct CapturedConsoleColors
        {
            public readonly bool HasForeground;
            public readonly ConsoleColor Foreground;
            public readonly bool HasBackground;
            public readonly ConsoleColor Background;

            public CapturedConsoleColors(bool HasForeground, ConsoleColor Foreground, bool HasBackground, ConsoleColor Background)
            {
                this.HasForeground = HasForeground;
                this.Foreground = Foreground;
                this.HasBackground = HasBackground;
                this.Background = Background;
            }
        }

        private static int GetDebuggerDisplayWidth()
        {
            try
            {
                int Width = Console.BufferWidth;
                if (Width <= 1)
                    Width = Console.WindowWidth;

                if (Width <= 1)
                    Width = 120;

                return Math.Min(Math.Max(Width, 40), 160);
            }
            catch
            {
                return 120;
            }
        }

        private static int GetDebuggerPanelWidth()
        {
            int Width = GetDebuggerDisplayWidth() - 1;
            return Math.Clamp(Width, 60, 110);
        }

        private static bool IsValidConsoleColor(ConsoleColor Color)
        {
            return Enum.IsDefined(typeof(ConsoleColor), Color);
        }

        private static CapturedConsoleColors CaptureConsoleColors()
        {
            bool HasForeground = false;
            bool HasBackground = false;
            ConsoleColor Foreground = default;
            ConsoleColor Background = default;

            try
            {
                Foreground = Console.ForegroundColor;
                HasForeground = IsValidConsoleColor(Foreground);
            }
            catch
            {
            }

            try
            {
                Background = Console.BackgroundColor;
                HasBackground = IsValidConsoleColor(Background);
            }
            catch
            {
            }

            return new CapturedConsoleColors(HasForeground, Foreground, HasBackground, Background);
        }

        private static void RestoreConsoleColors(CapturedConsoleColors Colors)
        {
            try
            {
                if (Colors.HasForeground)
                    Console.ForegroundColor = Colors.Foreground;

                if (Colors.HasBackground)
                    Console.BackgroundColor = Colors.Background;

                if (!Colors.HasForeground && !Colors.HasBackground)
                    Console.ResetColor();
            }
            catch
            {
            }
        }

        private static void SetConsoleColors(ConsoleColor? Foreground, ConsoleColor? Background)
        {
            try
            {
                if (Foreground.HasValue)
                    Console.ForegroundColor = Foreground.Value;

                if (Background.HasValue)
                    Console.BackgroundColor = Background.Value;
            }
            catch
            {
            }
        }

        private static string TrimDebuggerSegment(string Text, int RemainingLength)
        {
            if (RemainingLength <= 0 || string.IsNullOrEmpty(Text))
                return string.Empty;

            if (Text.Length <= RemainingLength)
                return Text;

            if (RemainingLength <= 3)
                return Text[..RemainingLength];

            return Text[..(RemainingLength - 3)] + "...";
        }

        private static DebuggerDisplayLine CreatePanelBorder(int PanelWidth, char Left, char Fill, char Right)
        {
            return new DebuggerDisplayLine()
                .Add(Left.ToString(), ConsoleColor.Cyan)
                .Add(new string(Fill, Math.Max(PanelWidth - 2, 0)), ConsoleColor.DarkCyan)
                .Add(Right.ToString(), ConsoleColor.Cyan);
        }

        private static DebuggerDisplayLine CreatePanelLine(int PanelWidth, ConsoleColor? ContentBackground, params DebuggerTextSegment[] Segments)
        {
            DebuggerDisplayLine Line = new DebuggerDisplayLine();
            int ContentWidth = Math.Max(PanelWidth - 4, 1);
            int Written = 0;

            Line.Add("│ ", ConsoleColor.Cyan);

            foreach (DebuggerTextSegment Segment in Segments)
            {
                if (Written >= ContentWidth)
                    break;

                string Text = TrimDebuggerSegment(Segment.Text, ContentWidth - Written);
                if (Text.Length == 0)
                    continue;

                Line.Add(Text, Segment.Foreground, Segment.Background ?? ContentBackground);
                Written += Text.Length;
            }

            if (Written < ContentWidth)
                Line.Add(new string(' ', ContentWidth - Written), null, ContentBackground);

            Line.Add(" │", ConsoleColor.Cyan);
            return Line;
        }

        private static DebuggerDisplayLine CreateInstructionLine(int PanelWidth, X86Instruction Instruction, bool Current)
        {
            ConsoleColor? Background = Current ? ConsoleColor.DarkBlue : null;
            ConsoleColor PrefixColor = Current ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
            ConsoleColor AddressColor = Current ? ConsoleColor.White : ConsoleColor.DarkGray;
            ConsoleColor MnemonicColor = Current ? ConsoleColor.Cyan : ConsoleColor.DarkCyan;
            ConsoleColor OperandColor = Current ? ConsoleColor.White : ConsoleColor.Gray;
            string Prefix = Current ? "=> " : "   ";
            string Mnemonic = Instruction.Mnemonic ?? string.Empty;
            string Operand = Instruction.Operand ?? string.Empty;

            if (string.IsNullOrWhiteSpace(Operand))
            {
                return CreatePanelLine(
                    PanelWidth,
                    Background,
                    new DebuggerTextSegment(Prefix, PrefixColor),
                    new DebuggerTextSegment($"0x{Instruction.Address:X16}", AddressColor),
                    new DebuggerTextSegment(": ", ConsoleColor.DarkGray),
                    new DebuggerTextSegment(Mnemonic, MnemonicColor));
            }

            return CreatePanelLine(
                PanelWidth,
                Background,
                new DebuggerTextSegment(Prefix, PrefixColor),
                new DebuggerTextSegment($"0x{Instruction.Address:X16}", AddressColor),
                new DebuggerTextSegment(": ", ConsoleColor.DarkGray),
                new DebuggerTextSegment(Mnemonic, MnemonicColor),
                new DebuggerTextSegment(" ", ConsoleColor.DarkGray),
                new DebuggerTextSegment(Operand, OperandColor));
        }

        internal static void ClearDebuggerStopDisplay()
        {
            ClearDebuggerStopDisplay(false);
        }

        internal static void PrepareDebuggerStopDisplayRefresh()
        {
            ClearDebuggerStopDisplay(true);
        }

        private static void ClearDebuggerStopDisplay(bool KeepDisplayTop)
        {
            lock (DebuggerConsoleLock)
            {
                if (!DebuggerStopDisplayActive && DebuggerStopDisplayReservedHeight <= 0 && DebuggerDirtyRows.Count == 0)
                {
                    if (!KeepDisplayTop)
                        DebuggerPendingStopDisplayTop = -1;

                    return;
                }

                CapturedConsoleColors Colors = CaptureConsoleColors();
                int PendingTop = -1;

                try
                {
                    int OriginalLeft = Console.CursorLeft;
                    int OriginalTop = Console.CursorTop;
                    int Width = GetDebuggerClearWidth();
                    DebuggerConsoleViewport Viewport = GetDebuggerConsoleViewport();
                    int DisplayTop = DebuggerStopDisplayTop;

                    if (KeepDisplayTop)
                    {
                        int MaxTop = GetDebuggerMaxPanelTop(Math.Max(DebuggerStopDisplayHeight, 1), Viewport);
                        PendingTop = Math.Min(Math.Max(DisplayTop, Viewport.Top), MaxTop);
                    }

                    ClearDebuggerDirtyRows(Viewport, Width);

                    int ClearHeight = Math.Max(DebuggerStopDisplayHeight, DebuggerStopDisplayReservedHeight);
                    int ClearStart = Math.Max(DisplayTop, Viewport.Top);
                    int ClearEnd = DisplayTop + ClearHeight;
                    if (DebuggerPromptTop >= DisplayTop)
                        ClearEnd = Math.Max(ClearEnd, DebuggerPromptTop + 1);

                    ClearEnd = Math.Min(ClearEnd + GetDebuggerPromptBottomReserve(Viewport), Viewport.BottomExclusive);
                    ClearDebuggerConsoleRows(ClearStart, ClearEnd, Width);
                    DebuggerDirtyRows.RemoveWhere(Row => Row >= ClearStart && Row < ClearEnd);

                    int RestoreTop = KeepDisplayTop && PendingTop >= 0 ? PendingTop : OriginalTop;
                    if (RestoreTop < Viewport.Top || RestoreTop >= Viewport.BottomExclusive)
                        RestoreTop = Math.Min(Math.Max(DisplayTop, Viewport.Top), Viewport.BottomExclusive - 1);

                    Console.SetCursorPosition(0, RestoreTop);
                    if (!KeepDisplayTop && OriginalLeft >= 0 && OriginalLeft < Width)
                        Console.SetCursorPosition(OriginalLeft, RestoreTop);
                }
                catch
                {
                }
                finally
                {
                    RestoreConsoleColors(Colors);
                    DebuggerStopDisplayActive = false;
                    DebuggerStopDisplayTop = 0;
                    DebuggerStopDisplayHeight = 0;
                    DebuggerStopDisplayReservedHeight = 0;
                    DebuggerPendingStopDisplayTop = KeepDisplayTop ? PendingTop : -1;
                    DebuggerPromptTop = -1;
                    DebuggerDirtyRows.Clear();
                }
            }
        }

        private static void WriteDebuggerDisplayLine(DebuggerDisplayLine Line, int Width, int ClearWidth)
        {
            int MaxLength = Math.Max(ClearWidth - 1, 1);
            int Written = 0;
            CapturedConsoleColors Colors = CaptureConsoleColors();

            try
            {
                foreach (DebuggerTextSegment Segment in Line.Segments)
                {
                    if (Written >= MaxLength)
                        break;

                    string Text = TrimDebuggerSegment(Segment.Text, Math.Min(Width - 1, MaxLength) - Written);
                    if (Text.Length == 0)
                        continue;

                    SetConsoleColors(Segment.Foreground, Segment.Background);
                    Console.Write(Text);
                    Written += Text.Length;
                }

                if (Written < MaxLength)
                {
                    RestoreConsoleColors(Colors);
                    Console.Write(new string(' ', MaxLength - Written));
                }
            }
            finally
            {
                RestoreConsoleColors(Colors);
            }
        }

        private static int GetDebuggerBufferHeight()
        {
            try
            {
                return Math.Max(Console.BufferHeight, 1);
            }
            catch
            {
                return 1;
            }
        }

        private static DebuggerConsoleViewport GetDebuggerConsoleViewport()
        {
            int BufferHeight = GetDebuggerBufferHeight();
            int WindowTop = 0;
            int WindowHeight = BufferHeight;

            try
            {
                WindowTop = Console.WindowTop;
                WindowHeight = Console.WindowHeight;
            }
            catch
            {
            }

            if (WindowTop < 0)
                WindowTop = 0;

            if (WindowTop >= BufferHeight)
                WindowTop = BufferHeight - 1;

            if (WindowHeight <= 0)
                WindowHeight = BufferHeight;

            if (WindowTop + WindowHeight > BufferHeight)
                WindowHeight = BufferHeight - WindowTop;

            if (WindowHeight <= 0)
                WindowHeight = 1;

            return new DebuggerConsoleViewport(WindowTop, WindowHeight);
        }

        private static int GetDebuggerClearWidth()
        {
            try
            {
                int Width = Console.BufferWidth;
                if (Width <= 1)
                    Width = Console.WindowWidth;

                return Math.Max(Width, 2);
            }
            catch
            {
                return GetDebuggerDisplayWidth();
            }
        }

        private static void ClearDebuggerConsoleRow(int Row, int Width)
        {
            try
            {
                if (Row < 0 || Row >= Console.BufferHeight)
                    return;

                Console.SetCursorPosition(0, Row);
                Console.Write(new string(' ', Math.Max(Width - 1, 1)));
                Console.SetCursorPosition(0, Row);
            }
            catch
            {
            }
        }

        private static void ClearDebuggerConsoleRows(int StartRow, int EndRow, int Width)
        {
            if (EndRow <= StartRow)
                return;

            for (int Row = StartRow; Row < EndRow; Row++)
                ClearDebuggerConsoleRow(Row, Width);
        }

        private static void MarkDebuggerDirtyRow(int Row)
        {
            if (Row < 0)
                return;

            DebuggerDirtyRows.Add(Row);
        }

        private static void ClearDebuggerDirtyRows(DebuggerConsoleViewport Viewport, int Width)
        {
            if (DebuggerDirtyRows.Count == 0)
                return;

            int BufferHeight = GetDebuggerBufferHeight();
            List<int> Rows = DebuggerDirtyRows
                .Where(Row => Row >= Viewport.Top && Row < Viewport.BottomExclusive && Row >= 0 && Row < BufferHeight)
                .OrderBy(Row => Row)
                .ToList();

            foreach (int Row in Rows)
            {
                ClearDebuggerConsoleRow(Row, Width);
                DebuggerDirtyRows.Remove(Row);
            }

            DebuggerDirtyRows.RemoveWhere(Row => Row < 0 || Row >= BufferHeight);
        }

        private static int GetDebuggerVisibleInputStart(int InputLength, int CursorIndex, int MaxVisibleLength)
        {
            if (MaxVisibleLength <= 0 || InputLength <= MaxVisibleLength)
                return 0;

            int VisibleStart = CursorIndex - MaxVisibleLength + 1;
            if (VisibleStart < 0)
                VisibleStart = 0;

            int MaxStart = InputLength - MaxVisibleLength;
            if (VisibleStart > MaxStart)
                VisibleStart = MaxStart;

            return VisibleStart;
        }

        private static void SetDebuggerPromptInput(StringBuilder Input, string Value, ref int CursorIndex)
        {
            Input.Clear();
            Input.Append(Value);
            CursorIndex = Input.Length;
        }

        private static void AddDebuggerCommandHistory(string Command)
        {
            if (string.IsNullOrWhiteSpace(Command))
                return;

            if (DebuggerCommandHistory.Count > 0 && string.Equals(DebuggerCommandHistory[^1], Command, StringComparison.Ordinal))
                return;

            DebuggerCommandHistory.Add(Command);
            if (DebuggerCommandHistory.Count > DebuggerCommandHistoryLimit)
                DebuggerCommandHistory.RemoveRange(0, DebuggerCommandHistory.Count - DebuggerCommandHistoryLimit);
        }

        private static void RenderDebuggerCommandPrompt(string Prompt, StringBuilder Input, int CursorIndex)
        {
            lock (DebuggerConsoleLock)
            {
                if (DebuggerPromptTop < 0)
                    return;

                int Width = GetDebuggerClearWidth();
                int MaxLineLength = Math.Max(Width - 1, 1);
                int PromptLength = Math.Min(Prompt.Length, MaxLineLength);
                int MaxVisibleInput = Math.Max(MaxLineLength - PromptLength, 0);
                int VisibleStart = GetDebuggerVisibleInputStart(Input.Length, CursorIndex, MaxVisibleInput);
                int VisibleLength = Math.Min(Math.Max(Input.Length - VisibleStart, 0), MaxVisibleInput);
                string VisibleInput = VisibleLength > 0 ? Input.ToString(VisibleStart, VisibleLength) : string.Empty;
                CapturedConsoleColors Colors = CaptureConsoleColors();

                try
                {
                    ClearDebuggerConsoleRow(DebuggerPromptTop, Width);
                    Console.SetCursorPosition(0, DebuggerPromptTop);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write(Prompt[..PromptLength]);
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(VisibleInput);

                    int CursorLeft = PromptLength + CursorIndex - VisibleStart;
                    if (CursorLeft < PromptLength)
                        CursorLeft = PromptLength;

                    if (CursorLeft >= MaxLineLength)
                        CursorLeft = MaxLineLength - 1;

                    MarkDebuggerDirtyRow(DebuggerPromptTop);
                    Console.SetCursorPosition(Math.Max(CursorLeft, 0), DebuggerPromptTop);
                }
                catch
                {
                }
                finally
                {
                    RestoreConsoleColors(Colors);
                }
            }
        }

        internal static void FlushPendingDebuggerInput()
        {
            try
            {
                int ReadCount = 0;
                while (Console.KeyAvailable && ReadCount < 4096)
                {
                    Console.ReadKey(true);
                    ReadCount++;
                }
            }
            catch
            {
            }
        }

        internal static string ReadDebuggerCommandLine(string Prompt)
        {
            MoveToDebuggerCommandPrompt();
            if (DebuggerPromptTop < 0)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write(Prompt);
                Console.ForegroundColor = ConsoleColor.White;
                string Result = Console.ReadLine()?.Trim() ?? string.Empty;
                AddDebuggerCommandHistory(Result);
                return Result;
            }

            StringBuilder Input = new();
            string DraftInput = string.Empty;
            int CursorIndex = 0;
            int HistoryIndex = DebuggerCommandHistory.Count;

            while (true)
            {
                RenderDebuggerCommandPrompt(Prompt, Input, CursorIndex);
                ConsoleKeyInfo Key = Console.ReadKey(true);

                if (Key.Key == ConsoleKey.Enter)
                {
                    string Result = Input.ToString().Trim();
                    AddDebuggerCommandHistory(Result);
                    ClearDebuggerCommandPromptLine();
                    return Result;
                }

                if (Key.Key == ConsoleKey.Escape)
                {
                    Input.Clear();
                    CursorIndex = 0;
                    HistoryIndex = DebuggerCommandHistory.Count;
                    DraftInput = string.Empty;
                    continue;
                }

                if (Key.Key == ConsoleKey.UpArrow)
                {
                    if (DebuggerCommandHistory.Count > 0 && HistoryIndex > 0)
                    {
                        if (HistoryIndex == DebuggerCommandHistory.Count)
                            DraftInput = Input.ToString();

                        HistoryIndex--;
                        SetDebuggerPromptInput(Input, DebuggerCommandHistory[HistoryIndex], ref CursorIndex);
                    }

                    continue;
                }

                if (Key.Key == ConsoleKey.DownArrow)
                {
                    if (HistoryIndex < DebuggerCommandHistory.Count)
                    {
                        HistoryIndex++;
                        SetDebuggerPromptInput(
                            Input,
                            HistoryIndex == DebuggerCommandHistory.Count ? DraftInput : DebuggerCommandHistory[HistoryIndex],
                            ref CursorIndex);
                    }

                    continue;
                }

                if (Key.Key == ConsoleKey.Backspace)
                {
                    if (CursorIndex > 0)
                    {
                        Input.Remove(CursorIndex - 1, 1);
                        CursorIndex--;
                    }

                    HistoryIndex = DebuggerCommandHistory.Count;
                    DraftInput = Input.ToString();
                    continue;
                }

                if (Key.Key == ConsoleKey.Delete)
                {
                    if (CursorIndex < Input.Length)
                        Input.Remove(CursorIndex, 1);

                    HistoryIndex = DebuggerCommandHistory.Count;
                    DraftInput = Input.ToString();
                    continue;
                }

                if (Key.Key == ConsoleKey.LeftArrow)
                {
                    if (CursorIndex > 0)
                        CursorIndex--;

                    continue;
                }

                if (Key.Key == ConsoleKey.RightArrow)
                {
                    if (CursorIndex < Input.Length)
                        CursorIndex++;

                    continue;
                }

                if (Key.Key == ConsoleKey.Home)
                {
                    CursorIndex = 0;
                    continue;
                }

                if (Key.Key == ConsoleKey.End)
                {
                    CursorIndex = Input.Length;
                    continue;
                }

                if (!char.IsControl(Key.KeyChar))
                {
                    Input.Insert(CursorIndex, Key.KeyChar);
                    CursorIndex++;
                    HistoryIndex = DebuggerCommandHistory.Count;
                    DraftInput = Input.ToString();
                }
            }
        }

        private static int GetDebuggerPromptBottomReserve(DebuggerConsoleViewport Viewport)
        {
            return Viewport.Height > 2 ? 2 : 1;
        }

        private static int GetDebuggerMaxPanelTop(int LineCount, DebuggerConsoleViewport Viewport)
        {
            int Reserve = GetDebuggerPromptBottomReserve(Viewport);
            return Viewport.Top + Math.Max(Viewport.Height - LineCount - Reserve, 0);
        }

        private static int GetDebuggerPanelTop(int LineCount, bool HasPreviousDisplay, DebuggerConsoleViewport Viewport)
        {
            int MaxTop = GetDebuggerMaxPanelTop(LineCount, Viewport);
            if (DebuggerPendingStopDisplayTop >= 0)
                return Math.Min(Math.Max(DebuggerPendingStopDisplayTop, Viewport.Top), MaxTop);

            if (HasPreviousDisplay && DebuggerStopDisplayTop >= Viewport.Top && DebuggerStopDisplayTop <= MaxTop)
                return DebuggerStopDisplayTop;

            return MaxTop;
        }

        private static int GetDebuggerPromptRow(int StartTop, int DisplayHeight, DebuggerConsoleViewport Viewport)
        {
            int MaxPromptTop = Viewport.Top + Math.Max(Viewport.Height - GetDebuggerPromptBottomReserve(Viewport), 0);
            int PromptTop = StartTop + DisplayHeight;
            if (PromptTop > MaxPromptTop)
                PromptTop = MaxPromptTop;

            return Math.Max(PromptTop, Viewport.Top);
        }

        internal static void MoveToDebuggerCommandPrompt()
        {
            lock (DebuggerConsoleLock)
            {
                if (!DebuggerStopDisplayActive || DebuggerStopDisplayHeight <= 0)
                {
                    DebuggerPromptTop = -1;
                    return;
                }

                int Width = GetDebuggerClearWidth();
                CapturedConsoleColors Colors = CaptureConsoleColors();

                try
                {
                    DebuggerConsoleViewport Viewport = GetDebuggerConsoleViewport();
                    int PromptTop = GetDebuggerPromptRow(DebuggerStopDisplayTop, DebuggerStopDisplayHeight, Viewport);

                    ClearDebuggerConsoleRow(PromptTop, Width);
                    Console.SetCursorPosition(0, PromptTop);
                    DebuggerPromptTop = PromptTop;
                }
                catch
                {
                    DebuggerPromptTop = -1;
                }
                finally
                {
                    RestoreConsoleColors(Colors);
                }
            }
        }

        internal static void ClearDebuggerCommandPromptLine()
        {
            lock (DebuggerConsoleLock)
            {
                if (!DebuggerStopDisplayActive || DebuggerPromptTop < 0)
                    return;

                int Width = GetDebuggerClearWidth();
                int PromptTop = DebuggerPromptTop;
                int CurrentTop = PromptTop;
                CapturedConsoleColors Colors = CaptureConsoleColors();

                try
                {
                    DebuggerConsoleViewport Viewport = GetDebuggerConsoleViewport();
                    CurrentTop = Console.CursorTop;
                    if (CurrentTop < PromptTop || CurrentTop >= Viewport.BottomExclusive)
                        CurrentTop = PromptTop;

                    for (int Row = PromptTop; Row <= CurrentTop && Row < Viewport.BottomExclusive; Row++)
                    {
                        ClearDebuggerConsoleRow(Row, Width);
                        DebuggerDirtyRows.Remove(Row);
                    }

                    Console.SetCursorPosition(0, PromptTop);
                }
                catch
                {
                }
                finally
                {
                    RestoreConsoleColors(Colors);
                    DebuggerPromptTop = -1;
                }
            }
        }

        private static void WriteDebuggerStopDisplay(IReadOnlyList<DebuggerDisplayLine> Lines)
        {
            lock (DebuggerConsoleLock)
            {
                if (Lines == null || Lines.Count == 0)
                    return;

                int Width = GetDebuggerDisplayWidth();
                int ClearWidth = GetDebuggerClearWidth();
                int StartTop = 0;
                int CurrentTop = 0;
                DebuggerConsoleViewport Viewport = GetDebuggerConsoleViewport();
                int PreviousTop = DebuggerStopDisplayTop;
                int PreviousHeight = Math.Max(DebuggerStopDisplayHeight, DebuggerStopDisplayReservedHeight);
                int PreviousPromptTop = DebuggerPromptTop;
                int WrittenLines = 0;
                bool HasPreviousDisplay = DebuggerStopDisplayActive || PreviousHeight > 0;
                CapturedConsoleColors Colors = CaptureConsoleColors();

                try
                {
                    CurrentTop = Console.CursorTop;
                    StartTop = GetDebuggerPanelTop(Lines.Count, HasPreviousDisplay, Viewport);
                    if (StartTop < Viewport.Top)
                        StartTop = Viewport.Top;
                }
                catch
                {
                    CurrentTop = Viewport.Top;
                    StartTop = Viewport.Top;
                    HasPreviousDisplay = false;
                    PreviousHeight = 0;
                    PreviousPromptTop = -1;
                }

                try
                {
                    ClearDebuggerDirtyRows(Viewport, ClearWidth);

                    int ClearStart = Math.Max(StartTop, Viewport.Top);
                    int ClearEnd = StartTop + Lines.Count + GetDebuggerPromptBottomReserve(Viewport);

                    if (HasPreviousDisplay)
                    {
                        ClearStart = Math.Max(Math.Min(ClearStart, PreviousTop), Viewport.Top);
                        ClearEnd = Math.Max(ClearEnd, PreviousTop + PreviousHeight + GetDebuggerPromptBottomReserve(Viewport));

                        if (PreviousPromptTop >= ClearStart)
                            ClearEnd = Math.Max(ClearEnd, PreviousPromptTop + GetDebuggerPromptBottomReserve(Viewport));
                    }

                    if (CurrentTop >= Viewport.Top && CurrentTop < Viewport.BottomExclusive)
                        ClearEnd = Math.Max(ClearEnd, CurrentTop + 1);

                    if (ClearEnd > Viewport.BottomExclusive)
                        ClearEnd = Viewport.BottomExclusive;

                    ClearDebuggerConsoleRows(ClearStart, ClearEnd, ClearWidth);
                    DebuggerDirtyRows.RemoveWhere(Row => Row >= ClearStart && Row < ClearEnd);

                    int LineLimit = Math.Min(Lines.Count, Math.Max(Viewport.BottomExclusive - StartTop - GetDebuggerPromptBottomReserve(Viewport), 0));
                    for (int i = 0; i < LineLimit; i++)
                    {
                        int Row = StartTop + i;
                        ClearDebuggerConsoleRow(Row, ClearWidth);
                        Console.SetCursorPosition(0, Row);
                        WrittenLines = i + 1;
                        WriteDebuggerDisplayLine(Lines[i], Width, ClearWidth);
                        MarkDebuggerDirtyRow(Row);
                    }

                    int PromptTop = GetDebuggerPromptRow(StartTop, WrittenLines, Viewport);
                    Console.SetCursorPosition(0, PromptTop);
                    DebuggerStopDisplayHeight = WrittenLines;
                    DebuggerStopDisplayReservedHeight = Math.Max(DebuggerStopDisplayReservedHeight, WrittenLines);
                }
                catch
                {
                    DebuggerStopDisplayHeight = 0;
                    DebuggerStopDisplayReservedHeight = Math.Max(DebuggerStopDisplayReservedHeight, WrittenLines);
                }
                finally
                {
                    RestoreConsoleColors(Colors);
                }

                DebuggerStopDisplayActive = DebuggerStopDisplayHeight > 0;
                DebuggerStopDisplayTop = StartTop;
                DebuggerPendingStopDisplayTop = -1;
                DebuggerPromptTop = -1;
            }
        }

        internal static void ShowDebuggerStopContext(string Reason, ulong Address)
        {
            int PanelWidth = GetDebuggerPanelWidth();
            List<DebuggerDisplayLine> Lines = new();
            string ReasonUpper = string.Equals(Reason, "Breakpoint hit", StringComparison.OrdinalIgnoreCase)
                ? "● BREAKPOINT"
                : "◆ STOPPED";
            ConsoleColor ReasonColor = string.Equals(Reason, "Breakpoint hit", StringComparison.OrdinalIgnoreCase)
                ? ConsoleColor.Red
                : ConsoleColor.Green;
            string ThreadText = Emulator == null ? string.Empty : $"  TID {Emulator.CurrentThreadId}";
            string Symbol = Handlers.FormatAddressWithSymbol(Address);

            Lines.Add(CreatePanelBorder(PanelWidth, '╭', '─', '╮'));
            Lines.Add(CreatePanelLine(
                PanelWidth,
                null,
                new DebuggerTextSegment(" Brovan Debugger ", ConsoleColor.White),
                new DebuggerTextSegment("— ", ConsoleColor.DarkGray),
                new DebuggerTextSegment(ReasonUpper, ReasonColor),
                new DebuggerTextSegment(ThreadText, ConsoleColor.Magenta)));
            Lines.Add(CreatePanelLine(
                PanelWidth,
                null,
                new DebuggerTextSegment(" at ", ConsoleColor.DarkGray),
                new DebuggerTextSegment(Symbol, ConsoleColor.Yellow)));
            Lines.Add(CreatePanelBorder(PanelWidth, '├', '─', '┤'));

            if (TryDecodeInstructionBlock(Address, 8, out X86Instruction[] Instructions))
            {
                for (int i = 0; i < Instructions.Length; i++)
                    Lines.Add(CreateInstructionLine(PanelWidth, Instructions[i], i == 0));
            }
            else
            {
                TryDecodeInstructionAt(Address, out X86Instruction Instruction, out _);
                if (Instruction.BytesLength != 0)
                    Lines.Add(CreateInstructionLine(PanelWidth, Instruction, true));
                else
                    Lines.Add(CreatePanelLine(
                        PanelWidth,
                        ConsoleColor.DarkBlue,
                        new DebuggerTextSegment("=> ", ConsoleColor.Yellow),
                        new DebuggerTextSegment($"0x{Address:X16}: ", ConsoleColor.White),
                        new DebuggerTextSegment("<disassembly unavailable>", ConsoleColor.Red)));
            }

            Lines.Add(CreatePanelBorder(PanelWidth, '╰', '─', '╯'));
            WriteDebuggerStopDisplay(Lines);
        }

        internal static bool IsCallInstruction(X86Instruction Instruction)
        {
            return string.Equals(Instruction.Mnemonic, "call", StringComparison.OrdinalIgnoreCase);
        }

        internal static void ClearTemporaryStepHook()
        {
            if (Emulator != null && TempStepHookHandle != IntPtr.Zero)
                Emulator._emulator.RemoveHook(TempStepHookHandle);

            TempStepHookHandle = IntPtr.Zero;
            TempStepTarget = 0;
        }

        internal static void PauseDebugger()
        {
            if (Emulator == null)
                return;

            DebuggerPausedThreadStates.Clear();
            DebuggerPausedThreadExitCodes.Clear();
            DebuggerPausedThreadOrder.Clear();
            DebuggerPausedThreadOrder.AddRange(Emulator.ThreadOrder);

            foreach (EmulatedThread Thread in Emulator.Threads.Values)
            {
                if (Thread == null || Thread.State == EmulatedThreadState.Terminated)
                    continue;

                DebuggerPausedThreadStates[Thread.ThreadId] = Thread.State;
                DebuggerPausedThreadExitCodes[Thread.ThreadId] = Thread.ExitCode;
            }

            ClearBreakpointSkip();
            ClearTemporaryStepHook();
            if (Emulator.CurrentThread != null)
                Emulator.SaveContext(Emulator.CurrentThread);

            DebuggerPaused = DebuggerPausedThreadStates.Count != 0 || DebuggerPausedThreadOrder.Count != 0;
            Emulator.StopEmulation();
        }

        private static void RestoreDebuggerPausedThreadStates()
        {
            if (!DebuggerPaused || Emulator == null)
                return;

            if (DebuggerPausedThreadOrder.Count != 0)
            {
                Emulator.ThreadOrder.Clear();
                Emulator.ThreadOrder.AddRange(DebuggerPausedThreadOrder);
            }

            foreach (KeyValuePair<uint, EmulatedThreadState> Entry in DebuggerPausedThreadStates)
            {
                if (!Emulator.Threads.TryGetValue(Entry.Key, out EmulatedThread Thread) || Thread == null)
                    continue;

                Thread.State = Entry.Value == EmulatedThreadState.Running
                    ? EmulatedThreadState.Ready
                    : Entry.Value;

                if (DebuggerPausedThreadExitCodes.TryGetValue(Entry.Key, out int ExitCode))
                    Thread.ExitCode = ExitCode;
            }

            DebuggerPausedThreadStates.Clear();
            DebuggerPausedThreadExitCodes.Clear();
            DebuggerPausedThreadOrder.Clear();
            DebuggerPaused = false;
        }

        internal static bool TryConvertDebuggerValue(Type fieldType, string value, out object converted)
        {
            converted = null;

            Type? NullableType = Nullable.GetUnderlyingType(fieldType);
            if (NullableType != null)
            {
                if (string.Equals(value, "null", StringComparison.OrdinalIgnoreCase))
                {
                    converted = null;
                    return true;
                }

                fieldType = NullableType;
            }

            if (fieldType.IsEnum)
            {
                if (TryParseAddress(value, out ulong enumValue))
                {
                    converted = Enum.ToObject(fieldType, enumValue);
                    return true;
                }

                if (Enum.TryParse(fieldType, value, true, out object parsed))
                {
                    converted = parsed;
                    return true;
                }

                return false;
            }

            if (fieldType == typeof(string))
            {
                converted = value;
                return true;
            }

            if (fieldType == typeof(bool))
            {
                if (!TryParseBooleanValue(value, out bool BoolValue))
                    return false;

                converted = BoolValue;
                return true;
            }

            if (!TryParseAddress(value, out ulong parsedValue))
                return false;

            if (fieldType == typeof(byte))
                converted = (byte)parsedValue;
            else if (fieldType == typeof(sbyte))
                converted = (sbyte)parsedValue;
            else if (fieldType == typeof(ushort))
                converted = (ushort)parsedValue;
            else if (fieldType == typeof(short))
                converted = (short)parsedValue;
            else if (fieldType == typeof(uint))
                converted = (uint)parsedValue;
            else if (fieldType == typeof(int))
                converted = (int)parsedValue;
            else if (fieldType == typeof(ulong))
                converted = parsedValue;
            else if (fieldType == typeof(long))
                converted = (long)parsedValue;
            else if (fieldType == typeof(UIntPtr))
                converted = Emulator._binary.Architecture == BinaryArchitecture.x64 ? new UIntPtr(parsedValue) : new UIntPtr((uint)parsedValue);
            else if (fieldType == typeof(IntPtr))
                converted = Emulator._binary.Architecture == BinaryArchitecture.x64 ? new IntPtr((long)parsedValue) : new IntPtr((int)parsedValue);
            else
                return false;

            return true;
        }

        public static bool TryBuildStructInstance(Type structType, string fieldAssignments, out object structInstance, out string errorMessage)
        {
            structInstance = null;
            errorMessage = string.Empty;

            if (structType == null)
            {
                errorMessage = "No struct type was provided.";
                return false;
            }

            if (!structType.IsValueType || structType.IsEnum)
            {
                errorMessage = $"{structType.FullName} is not a struct type.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(fieldAssignments))
            {
                errorMessage = "No field assignments were provided.";
                return false;
            }

            structInstance = Activator.CreateInstance(structType);

            var fields = structType.GetFields(BindingFlags.Public | BindingFlags.Instance);
            var fieldLookup = fields.ToDictionary(f => f.Name, f => f, StringComparer.OrdinalIgnoreCase);

            string[] assignments = fieldAssignments.Split('&', StringSplitOptions.RemoveEmptyEntries);
            foreach (string assignment in assignments)
            {
                int splitIndex = assignment.IndexOf('=');
                if (splitIndex <= 0 || splitIndex == assignment.Length - 1)
                {
                    errorMessage = $"Invalid assignment: {assignment}";
                    return false;
                }

                string fieldName = assignment.Substring(0, splitIndex).Trim();
                string fieldValue = assignment.Substring(splitIndex + 1).Trim();

                if (!fieldLookup.TryGetValue(fieldName, out FieldInfo field))
                {
                    errorMessage = $"Field not found: {fieldName}";
                    return false;
                }

                if (!TryConvertDebuggerValue(field.FieldType, fieldValue, out object converted))
                {
                    errorMessage = $"Unsupported or invalid value for {fieldName}: {fieldValue}";
                    return false;
                }

                field.SetValue(structInstance, converted);
            }

            return true;
        }

        public static bool TryResolveSymbol(string Input, out ulong Address)
        {
            Address = 0;

            if (string.IsNullOrWhiteSpace(Input))
                return false;

            if (Binary.FileFormat != BinaryFormat.PE)
                return false;

            if (Emulator?.WinHelper == null)
                return false;

            string ModuleName = null;
            string ExportName = null;
            ulong Offset = 0;

            string Working = Input;

            int Plus = Working.LastIndexOf('+');
            if (Plus > 0 && Plus < Working.Length - 1)
            {
                string OffsetString = Working.Substring(Plus + 1);
                if (!ulong.TryParse(OffsetString.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? OffsetString.Substring(2) : OffsetString, System.Globalization.NumberStyles.HexNumber, null, out Offset))
                {
                    return false;
                }

                Working = Working.Substring(0, Plus);
            }

            int Hash = Working.IndexOf('#');
            if (Hash > 0 && Hash < Working.Length - 1)
            {
                string ModNamePart = Working.Substring(0, Hash);
                string SubQuery = Working.Substring(Hash + 1);

                WinModule SubMod = null;
                foreach (WinModule Mod in Emulator.WinHelper.WinModules)
                {
                    if (Mod.Name.Equals(ModNamePart, StringComparison.OrdinalIgnoreCase))
                    {
                        SubMod = Mod;
                        break;
                    }
                }

                if (SubMod != null && TryResolveModuleSubQuery(SubMod, SubQuery, out ulong SubAddr))
                {
                    Address = SubAddr + Offset;
                    return true;
                }

                return false;
            }

            int Bang = Working.IndexOf('!');
            if (Bang > 0 && Bang < Working.Length - 1)
            {
                ModuleName = Working.Substring(0, Bang);
                ExportName = Working.Substring(Bang + 1);
            }
            else
            {
                ModuleName = Working;
            }

            WinModule Module = null;

            foreach (WinModule Mod in Emulator.WinHelper.WinModules)
            {
                if (Mod.Name.Equals(ModuleName, StringComparison.OrdinalIgnoreCase))
                {
                    Module = Mod;
                    break;
                }
            }

            if (Module == null)
                return false;

            if (string.IsNullOrEmpty(ExportName))
            {
                Address = Module.MappedBase + Offset;
                return true;
            }

            ulong ExportAddress = Emulator.WinHelper.GetExportAddress(Module, ExportName);
            if (ExportAddress == 0)
                return false;

            Address = ExportAddress + Offset;
            return true;
        }

        private static readonly Dictionary<string, int> DataDirectoryNames = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            { "Export",       0 }, { "ExportTable",  0 },
            { "Import",       1 }, { "ImportTable",  1 },
            { "Resource",     2 },
            { "Exception",    3 },
            { "Security",     4 }, { "Certificate",  4 },
            { "BaseReloc",    5 }, { "Reloc",        5 },
            { "Debug",        6 },
            { "TLS",          9 }, { "ThreadLocalStorage", 9 },
            { "LoadConfig",  10 },
            { "BoundImport", 11 },
            { "IAT",         12 },
            { "DelayImport", 13 },
            { "CLR",         14 }, { "DotNet",       14 },
        };

        private static bool TryResolveModuleSubQuery(WinModule Module, string SubQuery, out ulong Address)
        {
            Address = 0;

            int Bang = SubQuery.IndexOf('!');
            if (Bang <= 0 || Bang >= SubQuery.Length - 1)
                return false;

            string Category = SubQuery.Substring(0, Bang).Trim();
            string Field = SubQuery.Substring(Bang + 1).Trim();

            if (string.IsNullOrEmpty(Field))
                return false;

            ulong Base = Module.MappedBase;
            if (Base == 0)
                return false;

            if (Category.Equals("Sections", StringComparison.OrdinalIgnoreCase) || Category.Equals("Section", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var KV in Module.Sections)
                {
                    PortableBinarySection Sec = KV.Value;
                    if (Sec.SectionName.Equals(Field, StringComparison.OrdinalIgnoreCase))
                    {
                        Address = Base + Sec.VirtualAddress;
                        return true;
                    }
                }
                return false;
            }

            uint ELfaNew = Emulator.ReadMemoryUInt(Base + 0x3C);
            if (ELfaNew == 0 || ELfaNew > 0x1000)
                return false;

            ulong OptHdrAddr = Base + ELfaNew + 4 + 20;
            if (Category.Equals("OptionalHeader", StringComparison.OrdinalIgnoreCase))
            {
                FieldInfo Fi = typeof(IMAGE_OPTIONAL_HEADER64).GetField(Field, BindingFlags.Public | BindingFlags.Instance) ?? typeof(IMAGE_OPTIONAL_HEADER32).GetField(Field, BindingFlags.Public | BindingFlags.Instance);
                if (Fi == null)
                    return false;

                Type HdrType = Module.Architecture == BinaryArchitecture.x86 ? typeof(IMAGE_OPTIONAL_HEADER32) : typeof(IMAGE_OPTIONAL_HEADER64);

                int FieldOffset = (int)Marshal.OffsetOf(HdrType, Field);
                Address = OptHdrAddr + (ulong)FieldOffset;
                return true;
            }

            if (Category.Equals("DataDirectory", StringComparison.OrdinalIgnoreCase) || Category.Equals("DataDir", StringComparison.OrdinalIgnoreCase))
            {
                int DirIndex = -1;
                if (DataDirectoryNames.TryGetValue(Field, out int NamedIdx))
                    DirIndex = NamedIdx;
                else if (int.TryParse(Field, out int ParsedIdx) && ParsedIdx >= 0 && ParsedIdx < 16)
                    DirIndex = ParsedIdx;

                if (DirIndex < 0)
                    return false;

                FieldInfo DirField = typeof(IMAGE_OPTIONAL_HEADER64).GetField("_DataDirectory", BindingFlags.NonPublic | BindingFlags.Instance)
                                  ?? typeof(IMAGE_OPTIONAL_HEADER64).GetField("_DataDirectory", BindingFlags.Public | BindingFlags.Instance);

                if (DirField != null)
                {
                    int DirArrayOffset = (int)Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER64), "_DataDirectory");
                    Address = OptHdrAddr + (ulong)(DirArrayOffset + DirIndex * 8);
                    return true;
                }

                Address = OptHdrAddr + 0x70 + (ulong)(DirIndex * 8);
                return true;
            }

            return false;
        }

        public static bool TryParseBaseExpression(string Input, out ulong Result)
        {
            Result = 0;

            if (Emulator == null)
                return false;

            int Plus = Input.LastIndexOf('+');
            int Minus = Input.LastIndexOf('-');

            int OpIndex = Math.Max(Plus, Minus);
            if (OpIndex <= 0 || OpIndex >= Input.Length - 1)
                return false;

            char Op = Input[OpIndex];
            string BaseName = Input.Substring(0, OpIndex).Trim();
            string OffsetString = Input.Substring(OpIndex + 1).Trim();

            if (!TryResolveBaseName(BaseName, out ulong BaseValue))
                return false;

            if (!TryParseOffset(OffsetString, out ulong Offset))
                return false;

            Result = Op == '+' ? (BaseValue + Offset) : (BaseValue - Offset);
            return true;
        }

        public static bool TryResolveBaseName(string Name, out ulong Value)
        {
            Value = 0;

            if (string.IsNullOrWhiteSpace(Name))
                return false;

            if (Name.Equals("PEB", StringComparison.OrdinalIgnoreCase) || Name.Equals("_PEB", StringComparison.OrdinalIgnoreCase))
            {
                Value = Emulator.PEB;
                return Value != 0;
            }

            if (Name.Equals("TEB", StringComparison.OrdinalIgnoreCase) || Name.Equals("_TEB", StringComparison.OrdinalIgnoreCase))
            {
                EmulatedThread Thread = Emulator.CurrentThread;
                if (Thread == null)
                    Value = 0;
                else
                    Value = WinEmulatedThread.TryGetState(Thread)?.Teb ?? 0;
                return Value != 0;
            }

            if (Name.Equals("ProcessParams", StringComparison.OrdinalIgnoreCase) || Name.Equals("RTL_USER_PROCESS_PARAMETERS", StringComparison.OrdinalIgnoreCase) || Name.Equals("_RTL_USER_PROCESS_PARAMETERS", StringComparison.OrdinalIgnoreCase))
            {
                Value = Emulator.ProcessParams;
                return Value != 0;
            }

            if (Name.Equals("KUSER_SHARED_DATA", StringComparison.OrdinalIgnoreCase) || Name.Equals("KUSER", StringComparison.OrdinalIgnoreCase))
            {
                Value = Emulator.KUSER_SHARED_DATA;
                return Value != 0;
            }

            return false;
        }

        public static bool TryParseOffset(string Input, out ulong Offset)
        {
            Offset = 0;

            if (string.IsNullOrWhiteSpace(Input))
                return false;

            if (Input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.TryParse(Input.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out Offset);

            return ulong.TryParse(Input, out Offset);
        }

        public static bool TryParseAddress(string Input, out ulong Result, bool ResolveSymbols = true)
        {
            if (string.IsNullOrWhiteSpace(Input))
            {
                Result = 0;
                return false;
            }

            if (ResolveSymbols)
            {
                if (TryResolveSymbol(Input, out Result))
                    return true;

                if (TryParseBaseExpression(Input, out Result))
                    return true;
            }

            if (Input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.TryParse(Input.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out Result);

            return ulong.TryParse(Input, out Result);
        }

        public static bool TryParseHexBytes(string HexText, out byte[] Bytes, out string ErrorMessage)
        {
            Bytes = Array.Empty<byte>();
            ErrorMessage = string.Empty;

            HexText = (HexText ?? string.Empty).Replace(" ", "").Replace("\t", "");

            if (HexText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                HexText = HexText.Substring(2);

            if (HexText.Length == 0 || HexText.Length % 2 != 0)
            {
                ErrorMessage = "Invalid hex string.";
                return false;
            }

            for (int Index = 0; Index < HexText.Length; Index++)
            {
                char CharValue = HexText[Index];
                bool IsHex = (CharValue >= '0' && CharValue <= '9') ||
                             (CharValue >= 'A' && CharValue <= 'F') ||
                             (CharValue >= 'a' && CharValue <= 'f');

                if (!IsHex)
                {
                    ErrorMessage = "Invalid hex string.";
                    return false;
                }
            }

            Bytes = new byte[HexText.Length / 2];

            for (int Index = 0; Index < Bytes.Length; Index++)
                Bytes[Index] = Convert.ToByte(HexText.Substring(Index * 2, 2), 16);

            return true;
        }

        public static bool TryGetBytes(string PatchText, out byte[] PatchBytes, out string ErrorMessage)
        {
            PatchBytes = Array.Empty<byte>();
            ErrorMessage = string.Empty;

            PatchText = (PatchText ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(PatchText))
            {
                ErrorMessage = "Empty patch string.";
                return false;
            }

            if (TryParseHexBytes(PatchText, out PatchBytes, out ErrorMessage))
                return true;

            return false;
        }

        public static IEnumerable<MemoryRegion> GetMappedRegions()
        {
            return Emulator._memory
                .Where(Region => Region.Size > 0)
                .OrderBy(Region => Region.BaseAddress);
        }

        public static void ListMemoryRegions(bool IncludeModules = false)
        {
            List<MemoryRegion> Regions = GetMappedRegions().ToList();
            if (Regions.Count == 0)
            {
                PrintHighlight("[-] No mapped regions.", true);
                return;
            }

            PrintHighlight("[*] Mapped regions:", true);
            foreach (MemoryRegion Region in Regions)
            {
                string ModuleName = string.Empty;
                if (IncludeModules)
                {
                    WinModule Module = Emulator?.WinHelper?.WinModules?.FirstOrDefault(Mod => Region.BaseAddress >= Mod.MappedBase && (Region.BaseAddress + Region.Size) <= Mod.MappedBase + Mod.SizeOfImage);
                    ModuleName = string.IsNullOrEmpty(Module?.Name) ? string.Empty : $", {Module.Name}";
                }

                Console.WriteLine($"0x{Region.BaseAddress:X} - 0x{Region.BaseAddress + Region.Size:X} ({Region.Size} bytes{ModuleName}) {Region.Protections}");
            }
        }

        public static bool TrySplitFirstArgument(string Input, out string First, out string Rest)
        {
            First = string.Empty;
            Rest = string.Empty;

            if (string.IsNullOrWhiteSpace(Input))
                return false;

            string Trimmed = Input.Trim();
            if (Trimmed.Length == 0)
                return false;

            char Quote = Trimmed[0];
            if (Quote == '"' || Quote == '\'')
            {
                int EndQuote = Trimmed.IndexOf(Quote, 1);
                if (EndQuote == -1)
                    return false;

                First = Trimmed.Substring(1, EndQuote - 1);
                Rest = Trimmed.Substring(EndQuote + 1).Trim();
                return true;
            }

            int SplitIndex = Trimmed.IndexOf(' ');
            if (SplitIndex < 0)
            {
                First = Trimmed;
                Rest = string.Empty;
                return true;
            }

            First = Trimmed.Substring(0, SplitIndex);
            Rest = Trimmed.Substring(SplitIndex + 1).Trim();
            return true;
        }

        public static bool TryParseFindStrArguments(string Arguments, out string Text, out bool Utf16, out int MaxResults)
        {
            Text = string.Empty;
            Utf16 = false;
            MaxResults = 50;

            if (!TrySplitFirstArgument(Arguments, out string First, out string Rest))
                return false;

            Text = First;
            if (string.IsNullOrEmpty(Rest))
                return true;

            string[] Tokens = Rest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (Tokens.Length == 0)
                return true;

            int TokenIndex = 0;
            string ModeToken = Tokens[0];
            if (ModeToken.Equals("utf16", StringComparison.OrdinalIgnoreCase) ||
                ModeToken.Equals("unicode", StringComparison.OrdinalIgnoreCase))
            {
                Utf16 = true;
                TokenIndex = 1;
            }
            else if (ModeToken.Equals("ascii", StringComparison.OrdinalIgnoreCase))
            {
                Utf16 = false;
                TokenIndex = 1;
            }

            if (TokenIndex < Tokens.Length && int.TryParse(Tokens[TokenIndex], out int ParsedMax) && ParsedMax > 0)
                MaxResults = ParsedMax;

            return true;
        }

        public static void FindStringMatches(string Text, bool Utf16, int MaxResults)
        {
            if (string.IsNullOrEmpty(Text))
            {
                PrintHighlight("[-] Text cannot be empty.", true);
                return;
            }

            byte[] Needle = Utf16
                ? Encoding.Unicode.GetBytes(Text)
                : Encoding.ASCII.GetBytes(Text);

            int Found = 0;
            byte[] Carry = Array.Empty<byte>();

            foreach (MemoryRegion Region in GetMappedRegions())
            {
                if (Found >= MaxResults)
                    break;

                ulong RegionStart = Region.BaseAddress;
                ulong RegionEnd = Region.BaseAddress + Region.Size;
                const int ChunkSize = 0x10000;

                for (ulong Cursor = RegionStart; Cursor < RegionEnd; Cursor += ChunkSize)
                {
                    if (Found >= MaxResults)
                        break;

                    int ReadSize = (int)Math.Min((ulong)ChunkSize, RegionEnd - Cursor);
                    byte[] Data;
                    try
                    {
                        Data = Emulator.ReadMemory(Cursor, (uint)ReadSize);
                    }
                    catch
                    {
                        Carry = Array.Empty<byte>();
                        continue;
                    }

                    if (Data.Length == 0)
                    {
                        Carry = Array.Empty<byte>();
                        continue;
                    }

                    byte[] BufferData;
                    if (Carry.Length > 0)
                    {
                        BufferData = new byte[Carry.Length + Data.Length];
                        Buffer.BlockCopy(Carry, 0, BufferData, 0, Carry.Length);
                        Buffer.BlockCopy(Data, 0, BufferData, Carry.Length, Data.Length);
                    }
                    else
                    {
                        BufferData = Data;
                    }

                    int Limit = BufferData.Length - Needle.Length;
                    for (int Offset = 0; Offset <= Limit; Offset++)
                    {
                        bool Match = true;
                        for (int Index = 0; Index < Needle.Length; Index++)
                        {
                            if (BufferData[Offset + Index] != Needle[Index])
                            {
                                Match = false;
                                break;
                            }
                        }

                        if (Match)
                        {
                            ulong MatchAddress = Cursor - (ulong)Carry.Length + (ulong)Offset;
                            Console.WriteLine($"0x{MatchAddress:X}");
                            Found++;
                            if (Found >= MaxResults)
                                break;
                        }
                    }

                    int CarrySize = Needle.Length > 1 ? Needle.Length - 1 : 0;
                    if (CarrySize > 0 && BufferData.Length >= CarrySize)
                    {
                        Carry = BufferData.Skip(BufferData.Length - CarrySize).ToArray();
                    }
                    else
                    {
                        Carry = Array.Empty<byte>();
                    }
                }
            }

            PrintHighlight(Found == 0 ? "[-] No matches found." : $"[+] Found {Found} match(es).", true);
        }

        public static bool TryPreprocessExpression(string Input, out string Processed)
        {
            Processed = Input;
            if (string.IsNullOrWhiteSpace(Input))
                return false;

            System.Text.RegularExpressions.MatchCollection Matches = System.Text.RegularExpressions.Regex.Matches(Input, @"[A-Za-z0-9_.!#]+");
            if (Matches.Count == 0)
                return true;

            StringBuilder Builder = new StringBuilder(Input.Length);
            int LastIndex = 0;
            foreach (System.Text.RegularExpressions.Match Match in Matches)
            {
                Builder.Append(Input, LastIndex, Match.Index - LastIndex);

                if (TryResolveSymbol(Match.Value, out ulong ValueSymbol))
                    Builder.Append($"0x{ValueSymbol:X}");
                else if (TryResolveBaseName(Match.Value, out ulong ValueBaseName))
                    Builder.Append($"0x{ValueBaseName:X}");
                else
                    Builder.Append(Match.Value);

                LastIndex = Match.Index + Match.Length;
            }

            Builder.Append(Input, LastIndex, Input.Length - LastIndex);
            Processed = Builder.ToString();
            return true;
        }

        private sealed class ExpressionParser
        {
            private readonly string Text;
            private int Position;

            public ExpressionParser(string Text)
            {
                this.Text = Text ?? string.Empty;
            }

            public bool TryParse(out ulong Value)
            {
                Value = 0;
                if (!TryParseOr(out Value))
                    return false;

                SkipWhiteSpace();
                return Position == Text.Length;
            }

            private bool TryParseOr(out ulong Value)
            {
                if (!TryParseXor(out Value))
                    return false;

                while (true)
                {
                    SkipWhiteSpace();
                    if (!TryConsume('|'))
                        return true;

                    if (!TryParseXor(out ulong Right))
                        return false;
                    Value |= Right;
                }
            }

            private bool TryParseXor(out ulong Value)
            {
                if (!TryParseAnd(out Value))
                    return false;

                while (true)
                {
                    SkipWhiteSpace();
                    if (!TryConsume('^'))
                        return true;

                    if (!TryParseAnd(out ulong Right))
                        return false;
                    Value ^= Right;
                }
            }

            private bool TryParseAnd(out ulong Value)
            {
                if (!TryParseShift(out Value))
                    return false;

                while (true)
                {
                    SkipWhiteSpace();
                    if (!TryConsume('&'))
                        return true;

                    if (!TryParseShift(out ulong Right))
                        return false;
                    Value &= Right;
                }
            }

            private bool TryParseShift(out ulong Value)
            {
                if (!TryParseAdd(out Value))
                    return false;

                while (true)
                {
                    SkipWhiteSpace();
                    if (TryConsume("<<"))
                    {
                        if (!TryParseAdd(out ulong Right) || Right > 63)
                            return false;
                        Value <<= (int)Right;
                        continue;
                    }

                    if (TryConsume(">>"))
                    {
                        if (!TryParseAdd(out ulong Right) || Right > 63)
                            return false;
                        Value >>= (int)Right;
                        continue;
                    }

                    return true;
                }
            }

            private bool TryParseAdd(out ulong Value)
            {
                if (!TryParseMul(out Value))
                    return false;

                while (true)
                {
                    SkipWhiteSpace();
                    if (TryConsume('+'))
                    {
                        if (!TryParseMul(out ulong Right))
                            return false;
                        Value = unchecked(Value + Right);
                        continue;
                    }

                    if (TryConsume('-'))
                    {
                        if (!TryParseMul(out ulong Right) || Right > Value)
                            return false;
                        Value -= Right;
                        continue;
                    }

                    return true;
                }
            }

            private bool TryParseMul(out ulong Value)
            {
                if (!TryParseUnary(out Value))
                    return false;

                while (true)
                {
                    SkipWhiteSpace();
                    if (TryConsume('*'))
                    {
                        if (!TryParseUnary(out ulong Right))
                            return false;
                        Value = unchecked(Value * Right);
                        continue;
                    }

                    if (TryConsume('/'))
                    {
                        if (!TryParseUnary(out ulong Right) || Right == 0)
                            return false;
                        Value /= Right;
                        continue;
                    }

                    return true;
                }
            }

            private bool TryParseUnary(out ulong Value)
            {
                SkipWhiteSpace();
                if (TryConsume('+'))
                    return TryParseUnary(out Value);

                if (TryConsume('-'))
                {
                    if (!TryParseUnary(out Value) || Value != 0)
                        return false;
                    return true;
                }

                return TryParsePrimary(out Value);
            }

            private bool TryParsePrimary(out ulong Value)
            {
                Value = 0;
                SkipWhiteSpace();

                if (TryConsume('('))
                {
                    if (!TryParseOr(out Value))
                        return false;

                    SkipWhiteSpace();
                    return TryConsume(')');
                }

                return TryParseNumber(out Value);
            }

            private bool TryParseNumber(out ulong Value)
            {
                Value = 0;
                SkipWhiteSpace();

                int Start = Position;
                if (Position + 2 <= Text.Length && Text[Position] == '0' && Position + 1 < Text.Length && (Text[Position + 1] == 'x' || Text[Position + 1] == 'X'))
                {
                    Position += 2;
                    int HexStart = Position;
                    while (Position < Text.Length && Uri.IsHexDigit(Text[Position]))
                        Position++;

                    if (Position == HexStart)
                        return false;

                    return ulong.TryParse(Text.Substring(HexStart, Position - HexStart), System.Globalization.NumberStyles.HexNumber, null, out Value);
                }

                while (Position < Text.Length && char.IsDigit(Text[Position]))
                    Position++;

                if (Position == Start)
                    return false;

                return ulong.TryParse(Text.Substring(Start, Position - Start), out Value);
            }

            private void SkipWhiteSpace()
            {
                while (Position < Text.Length && char.IsWhiteSpace(Text[Position]))
                    Position++;
            }

            private bool TryConsume(char Value)
            {
                if (Position >= Text.Length || Text[Position] != Value)
                    return false;

                Position++;
                return true;
            }

            private bool TryConsume(string Value)
            {
                if (Position + Value.Length > Text.Length)
                    return false;

                for (int i = 0; i < Value.Length; i++)
                {
                    if (Text[Position + i] != Value[i])
                        return false;
                }

                Position += Value.Length;
                return true;
            }
        }

        public static bool TryEvaluateExpression(string Expression, out ulong Result)
        {
            Result = 0;
            if (string.IsNullOrWhiteSpace(Expression))
                return false;

            ExpressionParser Parser = new ExpressionParser(Expression);
            return Parser.TryParse(out Result);
        }

        public static bool IsShowInstrsRangeAllowed(ulong Address)
        {
            if (ShowInstrsRanges.Count == 0)
                return false;

            foreach ((ulong Start, ulong End) in ShowInstrsRanges)
            {
                if (Address >= Start && Address <= End)
                    return true;
            }

            return false;
        }

        private static bool IsShowInstrsModuleAllowed(string Name)
        {
            if (!ShowInstrsFilterEnabled)
                return false;

            if (string.IsNullOrEmpty(Name))
                return false;

            if (ShowInstrsModuleFilter.Contains(Name))
                return true;

            string FileName = Path.GetFileName(Name);
            if (!string.IsNullOrEmpty(FileName) && ShowInstrsModuleFilter.Contains(FileName))
                return true;

            string NoExt = Path.GetFileNameWithoutExtension(FileName);
            return !string.IsNullOrEmpty(NoExt) && ShowInstrsModuleFilter.Contains(NoExt);
        }

        public static bool IsShowInstrsModuleAllowed(WinModule Module)
        {
            return IsShowInstrsModuleAllowed(Module?.Name);
        }

        public static bool IsShowInstrsModuleAllowed(string ModuleName, string ModulePath)
        {
            if (IsShowInstrsModuleAllowed(ModuleName))
                return true;

            return IsShowInstrsModuleAllowed(ModulePath);
        }

        public static bool IsShowInstrsAllowed(ulong Address, WinModule Module)
        {
            if (ShowInstrsModuleFilter.Count == 0 && ShowInstrsRanges.Count == 0)
                return true;

            if (IsShowInstrsRangeAllowed(Address))
                return true;

            return IsShowInstrsModuleAllowed(Module);
        }

        public static bool IsShowInstrsAllowed(ulong Address, string ModuleName, string ModulePath)
        {
            if (ShowInstrsModuleFilter.Count == 0 && ShowInstrsRanges.Count == 0)
                return true;

            if (IsShowInstrsRangeAllowed(Address))
                return true;

            return IsShowInstrsModuleAllowed(ModuleName, ModulePath);
        }

        public static void ShowBinaryInfoSummary()
        {
            int FunctionCount = Binary?.Functions?.Length ?? 0;
            int ExportCount = Binary?.ExportFunctions?.Length ?? 0;
            int ImportCount = Binary?.PE?.ImportFunctions?.Count ?? 0;
            int SectionCount = Binary?.PE?.Sections?.Length ?? 0;

            PrintHighlight("[*] Binary info summary:", true);
            Console.WriteLine($"Path      : {Binary?.Location}");
            Console.WriteLine($"Format    : {Binary?.FileFormat}");
            Console.WriteLine($"Arch      : {Binary?.Architecture}");
            Console.WriteLine($"Entry RVA : 0x{Binary?.EntryPoint ?? 0:X}");
            Console.WriteLine($"Functions : {FunctionCount}");
            Console.WriteLine($"Exports   : {ExportCount}");
            Console.WriteLine($"Imports   : {ImportCount}");
            Console.WriteLine($"Sections  : {SectionCount}");

            if (Binary?.PE?.DotNetStatus == DotNetStatus.DotNet)
                Console.WriteLine($".NET funcs: {Binary.DotNet?.DotNetFunctions?.Length ?? 0}");
        }

        public static void ShowFunctionInfo(BinaryFunction[] Functions, string Title)
        {
            if (Functions == null || Functions.Length == 0)
            {
                PrintHighlight($"[-] No {Title} found.", true);
                return;
            }

            PrintHighlight($"[*] {Title} ({Functions.Length}):", true);
            foreach (BinaryFunction function in Functions.OrderBy(f => f.Address).Take(100))
                Console.WriteLine($"0x{function.Address:X16}  {function.FunctionName}");

            if (Functions.Length > 100)
                PrintHighlight($"[*] Showing first 100 of {Functions.Length} {Title.ToLowerInvariant()}.", true);
        }

        public static void ShowDotNetFunctionInfo(DotNetFunction[] Functions, string Title)
        {
            if (Functions == null || Functions.Length == 0)
            {
                PrintHighlight($"[-] No {Title} found.", true);
                return;
            }

            PrintHighlight($"[*] {Title} ({Functions.Length}):", true);

            foreach (DotNetFunction Function in Functions.OrderBy(Function => Function.RVA).Take(100))
            {
                Console.WriteLine($"{Function.DeclaringType}::{Function.FunctionName}");
                Console.WriteLine($"    RVA:        0x{Function.RVA:X8}");
                Console.WriteLine($"    FileOffset: 0x{Function.FileOffset:X8}");
                Console.WriteLine($"    Token:      0x{Function.Token:X8}");
                Console.WriteLine($"    Assembly:   {Function.AssemblyName}");
                Console.WriteLine($"    Parameters: {Function.ParameterCount}");
                Console.WriteLine($"    Locals:     {Function.LocalsCount}");
                Console.WriteLine($"    IL Size:    {Function.CodeSize}");
                Console.WriteLine($"    Instance:   {Function.IsInstance}");
                Console.WriteLine($"    Flags:      0x{Function.Flags:X4}");
                Console.WriteLine($"    ImplFlags:  {Function.ImplFlags}");
                Console.WriteLine();
            }

            if (Functions.Length > 100)
                PrintHighlight($"[*] Showing first 100 of {Functions.Length} {Title.ToLowerInvariant()}.", true);
        }
        public static bool TryParseThreadId(string Input, out uint ThreadId)
        {
            ThreadId = 0;
            if (Emulator == null || string.IsNullOrWhiteSpace(Input))
                return false;

            if (Input.Equals("current", StringComparison.OrdinalIgnoreCase) || Input == ".")
            {
                if (Emulator.CurrentThreadId < 0)
                    return false;

                ThreadId = (uint)Emulator.CurrentThreadId;
                return true;
            }

            if (!TryParseAddress(Input, out ulong Parsed, false) || Parsed > uint.MaxValue)
                return false;

            ThreadId = (uint)Parsed;
            return true;
        }

        public static bool IsAllThreadsTarget(string Input)
        {
            return !string.IsNullOrWhiteSpace(Input) && Input.Equals("all", StringComparison.OrdinalIgnoreCase);
        }

        public static void RefreshThreadContext(EmulatedThread Thread)
        {
            if (Emulator == null || Thread == null || Thread.Context == null)
                return;

            if (Emulator.CurrentThreadId == (int)Thread.ThreadId)
                Emulator.SaveContext(Thread);
        }

        public static ulong GetThreadInstructionPointer(EmulatedThread Thread)
        {
            return Thread?.Context?.RIP ?? 0;
        }

        public static ulong GetThreadStackPointer(EmulatedThread Thread)
        {
            return Thread?.Context?.RSP ?? 0;
        }

        public static string FormatThreadName(EmulatedThread Thread)
        {
            if (Thread == null)
                return string.Empty;

            return string.IsNullOrWhiteSpace(Thread.Name) ? $"Thread_{Thread.ThreadId}" : Thread.Name;
        }

        public static string FormatThreadWaitReason(EmulatedThread Thread)
        {
            if (Thread == null)
                return "-";

            if (Thread.GuestState is LinuxThreadState LinuxState)
            {
                if (LinuxState.FutexWaitActive)
                    return $"futex uaddr=0x{LinuxState.FutexAddress:X}";

                if (LinuxState.EpollWaitActive)
                    return $"epoll fd={LinuxState.EpollWaitDescriptor}";

                if (LinuxState.SigsuspendActive)
                    return "sigsuspend";

                if (LinuxState.DispatchSignal)
                    return $"signal {LinuxState.PendingSignal.Signal}";
            }
            else if (Thread.GuestState is WindowsThreadState WindowsState)
            {
                if (WindowsState.WaitObjects != null && WindowsState.WaitObjects.Count > 0)
                    return $"objects={WindowsState.WaitObjects.Count}";

                if (WindowsState.WorkerFactoryWaitActive)
                    return $"worker-factory 0x{WindowsState.WorkerFactoryHandle:X}";

                if (WindowsState.AlertByThreadIdWaitActive)
                    return $"alertbythreadid 0x{WindowsState.AlertByThreadIdAddress:X}";

                if (WindowsState.ApcAlertable)
                    return "alertable";
            }

            if (Thread.WaitActive)
            {
                string Deadline = Thread.WaitDeadline < 0 ? "inf" : Thread.WaitDeadline.ToString();
                if (Thread.WaitHandles != null && Thread.WaitHandles.Count > 0)
                    return $"wait handles={Thread.WaitHandles.Count} deadline={Deadline}";

                return $"wait deadline={Deadline}";
            }

            return "-";
        }

        public static string FormatThreadFlags(EmulatedThread Thread)
        {
            if (Thread == null)
                return "-";

            List<string> Flags = new List<string>();
            if (Emulator != null && Emulator.CurrentThreadId == (int)Thread.ThreadId)
                Flags.Add("current");
            if (Thread.WaitActive)
                Flags.Add("waiting");
            if (Thread.SuspendCount > 0)
                Flags.Add($"suspend={Thread.SuspendCount}");
            if (Thread.SwitchingContext)
                Flags.Add("switchctx");

            if (Thread.GuestState is LinuxThreadState LinuxState)
            {
                if (LinuxState.IsHandlingSignal)
                    Flags.Add($"signal-depth={LinuxState.SignalNesting}");
                if (LinuxState.PendingSignals != null && LinuxState.PendingSignals.Count > 0)
                    Flags.Add($"pending-signals={LinuxState.PendingSignals.Count}");
            }
            else if (Thread.GuestState is WindowsThreadState WindowsState)
            {
                if (WindowsState.IsHandlingException)
                    Flags.Add($"exception-depth={WindowsState.ExceptionNesting}");
                if (WindowsState.PendingUserApcs != null && WindowsState.PendingUserApcs.Count > 0)
                    Flags.Add($"apc={WindowsState.PendingUserApcs.Count}");
            }

            return Flags.Count == 0 ? "-" : string.Join(",", Flags);
        }

        public static bool TryGetThreadArgument(string[] Args, int Index, out EmulatedThread Thread)
        {
            Thread = null;
            if (Args.Length <= Index || !TryParseThreadId(Args[Index], out uint ThreadId))
                return false;

            return Emulator != null && Emulator.TryGetThread(ThreadId, out Thread) && Thread != null;
        }

        public static bool TryParseHandleValue(string Input, out ulong Value)
        {
            Value = 0;
            return !string.IsNullOrWhiteSpace(Input) && TryParseAddress(Input, out Value, false);
        }

        public static bool TryParseBooleanValue(string Input, out bool Value)
        {
            Value = false;
            if (string.IsNullOrWhiteSpace(Input))
                return false;

            switch (Input.Trim().ToLowerInvariant())
            {
                case "1":
                case "true":
                case "yes":
                case "y":
                case "on":
                case "set":
                case "enabled":
                case "enable":
                    Value = true;
                    return true;

                case "0":
                case "false":
                case "no":
                case "n":
                case "off":
                case "clear":
                case "disabled":
                case "disable":
                    Value = false;
                    return true;
            }

            return false;
        }

        public static bool TryParseAccessMaskValue(string Input, out AccessMask Value)
        {
            Value = AccessMask.None;
            if (string.IsNullOrWhiteSpace(Input))
                return false;

            if (TryParseAddress(Input, out ulong NumericValue, false))
            {
                Value = (AccessMask)unchecked((uint)NumericValue);
                return true;
            }

            AccessMask Result = AccessMask.None;
            string[] Parts = Input.Split(new[] { '|', ',', '+' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (Parts.Length == 0)
                Parts = new[] { Input.Trim() };

            foreach (string Part in Parts)
            {
                if (!Enum.TryParse(Part, true, out AccessMask Parsed))
                    return false;

                Result |= Parsed;
            }

            Value = Result;
            return true;
        }

        public static string FormatWindowsHandleFlags(ObjectHandleFlags Flags)
        {
            if (Flags == ObjectHandleFlags.None)
                return "-";

            return Flags.ToString();
        }

        public static string FormatWindowsAccessMask(AccessMask Mask)
        {
            return Mask == AccessMask.None ? "None" : $"{Mask} (0x{(uint)Mask:X})";
        }

        public static string FormatLinuxDescriptorFlags(bool CloseOnExec, int StatusFlags)
        {
            List<string> Flags = new List<string>();
            if (CloseOnExec)
                Flags.Add("cloexec");
            if ((StatusFlags & 0x800) != 0)
                Flags.Add("nonblock");
            if ((StatusFlags & 0x400) != 0)
                Flags.Add("append");
            if ((StatusFlags & 0x2000) != 0)
                Flags.Add("async");

            return Flags.Count == 0 ? "-" : string.Join(",", Flags);
        }

        internal static bool TryGetPrivateFieldValue<T>(object Instance, string FieldName, out T Value)
        {
            Value = default;
            if (Instance == null)
                return false;

            FieldInfo Field = FindInstanceField(Instance.GetType(), FieldName);
            if (Field == null)
                return false;

            object RawValue = Field.GetValue(Instance);
            if (RawValue is T TypedValue)
            {
                Value = TypedValue;
                return true;
            }

            if (RawValue == null && (!typeof(T).IsValueType || Nullable.GetUnderlyingType(typeof(T)) != null))
                return true;

            return false;
        }

        internal static List<KeyValuePair<ulong, FileDescriptorEntry>> GetLinuxDescriptorSnapshot(FileDescriptorTable Table)
        {
            if (TryGetPrivateFieldValue(Table, "DescriptorToEntry", out Dictionary<ulong, FileDescriptorEntry> Entries))
            {
                return Entries
                    .OrderBy(Pair => Pair.Key)
                    .Select(Pair => new KeyValuePair<ulong, FileDescriptorEntry>(Pair.Key, Pair.Value))
                    .ToList();
            }

            return Table.EnumerateDescriptors()
                .Select(Descriptor => new KeyValuePair<ulong, FileDescriptorEntry>(Descriptor, Table.GetEntry(Descriptor)))
                .Where(Pair => Pair.Value != null)
                .OrderBy(Pair => Pair.Key)
                .ToList();
        }

        internal static bool TryGetWindowsHandleObjects(object Manager, out Dictionary<ulong, IHandleObject> Objects)
        {
            return TryGetPrivateFieldValue(Manager, "HandleToObject", out Objects);
        }

        internal static bool TryGetWindowsHandlePermissions(object Manager, out Dictionary<ulong, AccessMask> Permissions)
        {
            return TryGetPrivateFieldValue(Manager, "HandleToPermissions", out Permissions);
        }

        internal static bool TryGetWindowsHandleFlags(object Manager, out Dictionary<ulong, ObjectHandleFlags> Flags)
        {
            return TryGetPrivateFieldValue(Manager, "HandleToFlags", out Flags);
        }

        internal static bool TryGetWindowsObjectIndex(object Manager, out Dictionary<string, List<ulong>> ObjectIndex)
        {
            return TryGetPrivateFieldValue(Manager, "ObjectIdToHandles", out ObjectIndex);
        }

        internal static bool TrySetDebuggerMember(object Instance, string MemberName, string Value, out string ErrorMessage)
        {
            ErrorMessage = string.Empty;
            if (Instance == null)
            {
                ErrorMessage = "Object is null.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(MemberName))
            {
                ErrorMessage = "Member name is empty.";
                return false;
            }

            FieldInfo Field = FindInstanceField(Instance.GetType(), MemberName);
            if (Field != null)
            {
                if (Field.IsInitOnly)
                {
                    ErrorMessage = $"Field {Field.Name} is readonly.";
                    return false;
                }

                if (!TryConvertDebuggerValue(Field.FieldType, Value, out object Converted))
                {
                    ErrorMessage = $"Cannot convert value to {Field.FieldType.Name}.";
                    return false;
                }

                Field.SetValue(Instance, Converted);
                return true;
            }

            PropertyInfo Property = FindInstanceProperty(Instance.GetType(), MemberName);
            if (Property != null)
            {
                MethodInfo Setter = Property.GetSetMethod(true);
                if (Setter == null)
                {
                    ErrorMessage = $"Property {Property.Name} is read-only.";
                    return false;
                }

                if (!TryConvertDebuggerValue(Property.PropertyType, Value, out object Converted))
                {
                    ErrorMessage = $"Cannot convert value to {Property.PropertyType.Name}.";
                    return false;
                }

                Setter.Invoke(Instance, new[] { Converted });
                return true;
            }

            ErrorMessage = $"No field or property named {MemberName} was found on {Instance.GetType().Name}.";
            return false;
        }

        internal static void PrintDebuggerObjectMembers(object Instance, int MaxDepth = 0)
        {
            if (Instance == null)
            {
                Console.WriteLine("<null>");
                return;
            }

            Console.WriteLine($"ObjectType:       {Instance.GetType().FullName}");
            foreach (FieldInfo Field in EnumerateInstanceFields(Instance.GetType()))
            {
                object Value;
                try
                {
                    Value = Field.GetValue(Instance);
                }
                catch (Exception Ex)
                {
                    Console.WriteLine($"field {Field.Name,-24} <error: {Ex.GetType().Name}>");
                    continue;
                }

                Console.WriteLine($"field {Field.Name,-24} {FormatDebuggerValue(Value)}");
            }

            foreach (PropertyInfo Property in EnumerateInstanceProperties(Instance.GetType()))
            {
                if (Property.GetIndexParameters().Length != 0)
                    continue;

                object Value;
                try
                {
                    MethodInfo Getter = Property.GetGetMethod(true);
                    if (Getter == null)
                        continue;

                    Value = Getter.Invoke(Instance, null);
                }
                catch (Exception Ex)
                {
                    Console.WriteLine($"prop  {Property.Name,-24} <error: {Ex.GetType().Name}>");
                    continue;
                }

                Console.WriteLine($"prop  {Property.Name,-24} {FormatDebuggerValue(Value)}");
            }
        }

        private static FieldInfo FindInstanceField(Type Type, string Name)
        {
            for (Type Current = Type; Current != null; Current = Current.BaseType)
            {
                FieldInfo Field = Current.GetField(Name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.IgnoreCase);
                if (Field != null)
                    return Field;
            }

            return null;
        }

        private static PropertyInfo FindInstanceProperty(Type Type, string Name)
        {
            for (Type Current = Type; Current != null; Current = Current.BaseType)
            {
                PropertyInfo Property = Current.GetProperty(Name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.IgnoreCase);
                if (Property != null)
                    return Property;
            }

            return null;
        }

        private static IEnumerable<FieldInfo> EnumerateInstanceFields(Type Type)
        {
            Stack<Type> Types = new Stack<Type>();
            for (Type Current = Type; Current != null; Current = Current.BaseType)
                Types.Push(Current);

            while (Types.Count > 0)
            {
                Type Current = Types.Pop();
                foreach (FieldInfo Field in Current.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                    yield return Field;
            }
        }

        private static IEnumerable<PropertyInfo> EnumerateInstanceProperties(Type Type)
        {
            Stack<Type> Types = new Stack<Type>();
            for (Type Current = Type; Current != null; Current = Current.BaseType)
                Types.Push(Current);

            HashSet<string> Seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (Types.Count > 0)
            {
                Type Current = Types.Pop();
                foreach (PropertyInfo Property in Current.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                {
                    if (Seen.Add(Property.Name))
                        yield return Property;
                }
            }
        }

        internal static string FormatDebuggerValue(object Value)
        {
            if (Value == null)
                return "<null>";
            if (Value is string StringValue)
                return string.IsNullOrEmpty(StringValue) ? "\"\"" : $"\"{StringValue}\"";
            if (Value is bool BoolValue)
                return BoolValue ? "true" : "false";
            if (Value is byte or sbyte or short or ushort or int or uint or long or ulong)
                return Value.ToString();
            if (Value is IntPtr IntPtrValue)
                return $"0x{IntPtrValue.ToInt64():X}";
            if (Value is UIntPtr UIntPtrValue)
                return $"0x{UIntPtrValue.ToUInt64():X}";
            if (Value is System.Collections.ICollection Collection)
                return $"{Value.GetType().Name} Count={Collection.Count}";

            return Value.ToString();
        }

        public static bool TryParseSyscallTarget(string Token, out uint? Number, out string Name)
        {
            Number = null;
            Name = null;

            if (string.IsNullOrWhiteSpace(Token))
                return false;

            if (TryParseAddress(Token, out ulong Value, false) && Value <= uint.MaxValue)
            {
                Number = (uint)Value;
                return true;
            }

            Name = Token.Trim();
            return true;
        }

        public static bool TryParseSyscallAction(string Token, out SyscallAction Action)
        {
            Action = SyscallAction.Allow;

            if (string.IsNullOrWhiteSpace(Token))
                return false;

            switch (Token.Trim().ToLowerInvariant())
            {
                case "allow":
                    Action = SyscallAction.Allow;
                    return true;

                case "deny":
                    Action = SyscallAction.Deny;
                    return true;

                case "modify":
                case "modifyargs":
                    Action = SyscallAction.ModifyArgs;
                    return true;

                case "log":
                case "logonly":
                    Action = SyscallAction.LogOnly;
                    return true;

                default:
                    return false;
            }
        }

        public static string ReadGuestAsciiString(ulong Address, int MaxLength = 512)
        {
            if (Address == 0)
                return "NULL";

            if (Emulator == null || !Emulator.IsRegionMapped(Address, 1))
                return $"0x{Address:X}";

            try
            {
                List<byte> Bytes = new List<byte>(Math.Min(MaxLength, 128));
                for (int Index = 0; Index < MaxLength; Index++)
                {
                    byte[] Value = Emulator.ReadMemory(Address + (ulong)Index, 1);
                    if (Value == null || Value.Length == 0 || Value[0] == 0)
                        break;

                    Bytes.Add(Value[0]);
                }

                return EscapeDebuggerString(Encoding.UTF8.GetString(Bytes.ToArray()));
            }
            catch
            {
                return $"0x{Address:X}";
            }
        }

        public static string EscapeDebuggerString(string Value)
        {
            if (Value == null)
                return string.Empty;

            StringBuilder Builder = new StringBuilder(Value.Length + 8);
            foreach (char Ch in Value)
            {
                switch (Ch)
                {
                    case '\\': Builder.Append("\\\\"); break;
                    case '"': Builder.Append("\\\""); break;
                    case '\r': Builder.Append("\\r"); break;
                    case '\n': Builder.Append("\\n"); break;
                    case '\t': Builder.Append("\\t"); break;
                    default:
                        if (char.IsControl(Ch))
                            Builder.Append($"\\x{(int)Ch:X2}");
                        else
                            Builder.Append(Ch);
                        break;
                }
            }

            return Builder.ToString();
        }

        public static bool IsSyscallFailure(SyscallHistoryEntry Entry)
        {
            if (!Entry.Implemented)
                return true;

            if (Entry.Guest == GuestOsKind.Linux)
            {
                long SignedReturn = Entry.Abi == SyscallAbi.X86
                    ? unchecked((int)(uint)Entry.ReturnValue)
                    : unchecked((long)Entry.ReturnValue);
                return SignedReturn < 0 && SignedReturn >= -4095;
            }

            if (Entry.Guest == GuestOsKind.Windows)
                return unchecked((int)(uint)Entry.ReturnValue) < 0;

            return false;
        }

        public static string FormatSyscallReturnValue(SyscallHistoryEntry Entry)
        {
            if (!Entry.Implemented)
                return Entry.Guest == GuestOsKind.Windows ? "not implemented" : "-ENOSYS?";

            if (Entry.Guest == GuestOsKind.Linux)
            {
                long SignedReturn = Entry.Abi == SyscallAbi.X86
                    ? unchecked((int)(uint)Entry.ReturnValue)
                    : unchecked((long)Entry.ReturnValue);

                if (SignedReturn < 0 && SignedReturn >= -4095)
                {
                    int Errno = (int)-SignedReturn;
                    string ErrnoName = Enum.GetName(typeof(LinuxErrno), Errno) ?? $"errno_{Errno}";
                    return $"-{ErrnoName} ({SignedReturn})";
                }

                return $"0x{Entry.ReturnValue:X}";
            }

            if (Entry.Guest == GuestOsKind.Windows)
            {
                uint Status = (uint)Entry.ReturnValue;
                string Name = Enum.GetName(typeof(NTSTATUS), Status);
                return Name == null ? $"0x{Status:X8}" : $"{Name} (0x{Status:X8})";
            }

            return $"0x{Entry.ReturnValue:X}";
        }

        public static string FormatSyscallHistoryEntry(SyscallHistoryEntry Entry, bool Detailed)
        {
            string Name = string.IsNullOrWhiteSpace(Entry.Name) ? $"sys_{Entry.Number:X}" : Entry.Name;
            string Args = FormatSyscallArguments(Entry);
            string ReturnValue = FormatSyscallReturnValue(Entry);
            string State = !Entry.Implemented ? "unknown" : (IsSyscallFailure(Entry) ? "failed" : "ok");
            string Rule = Entry.HandledByRule ? " rule" : string.Empty;

            if (Detailed)
                return $"#{Entry.Sequence} tid={Entry.ThreadId} {Entry.Guest}/{Entry.Abi} rip=0x{Entry.Rip:X} {Name}(0x{Entry.Number:X}) {State}{Rule}\n    args: {Args}\n    ret : {ReturnValue}";

            return $"#{Entry.Sequence,-6} tid={Entry.ThreadId,-4} {Entry.Guest,-7} {Name,-28} {TrimForColumn(Args, 72),-72} -> {ReturnValue}{Rule}";
        }

        public static string FormatSyscallArguments(SyscallHistoryEntry Entry)
        {
            return FormatRawArguments(Entry?.Args);
        }

        private static string FormatRawArguments(ulong[] Args)
        {
            if (Args == null || Args.Length == 0)
                return string.Empty;

            return string.Join(", ", Args.Select((Value, Index) => $"arg{Index}=0x{Value:X}"));
        }

        private static string TrimForColumn(string Text, int MaxLength)
        {
            if (string.IsNullOrEmpty(Text) || Text.Length <= MaxLength)
                return Text ?? string.Empty;

            return Text.Substring(0, Math.Max(0, MaxLength - 3)) + "...";
        }

        public static string FormatOnOff(bool Value)
        {
            return Value ? "on" : "off";
        }

    }
}
