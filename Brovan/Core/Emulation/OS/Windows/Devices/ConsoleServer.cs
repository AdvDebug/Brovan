using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    // INPUT_RECORD. Non-key events keep their raw 16-byte payload.
    public struct ConsoleInputRecord
    {
        public const int Size = 20;

        public ushort EventType;
        public bool KeyDown;
        public ushort RepeatCount;
        public ushort VirtualKey;
        public ushort ScanCode;
        public char Character;
        public uint ControlKeyState;
        public ulong PayloadLow;
        public ulong PayloadHigh;

        public readonly bool IsKey => EventType == ConsoleState.KeyEvent;

        public static ConsoleInputRecord Key(bool Down, ushort VirtualKey, ushort ScanCode, char Character, uint ControlKeyState)
        {
            return new ConsoleInputRecord
            {
                EventType = ConsoleState.KeyEvent,
                KeyDown = Down,
                RepeatCount = 1,
                VirtualKey = VirtualKey,
                ScanCode = ScanCode,
                Character = Character,
                ControlKeyState = ControlKeyState
            };
        }

        public static ConsoleInputRecord Read(ReadOnlySpan<byte> Source)
        {
            ConsoleInputRecord Record = new ConsoleInputRecord { EventType = BinaryPrimitives.ReadUInt16LittleEndian(Source) };
            if (!Record.IsKey)
            {
                Record.PayloadLow = BinaryPrimitives.ReadUInt64LittleEndian(Source.Slice(0x04));
                Record.PayloadHigh = BinaryPrimitives.ReadUInt64LittleEndian(Source.Slice(0x0C));
                return Record;
            }

            Record.KeyDown = BinaryPrimitives.ReadUInt32LittleEndian(Source.Slice(0x04)) != 0;
            Record.RepeatCount = BinaryPrimitives.ReadUInt16LittleEndian(Source.Slice(0x08));
            Record.VirtualKey = BinaryPrimitives.ReadUInt16LittleEndian(Source.Slice(0x0A));
            Record.ScanCode = BinaryPrimitives.ReadUInt16LittleEndian(Source.Slice(0x0C));
            Record.Character = (char)BinaryPrimitives.ReadUInt16LittleEndian(Source.Slice(0x0E));
            Record.ControlKeyState = BinaryPrimitives.ReadUInt32LittleEndian(Source.Slice(0x10));
            return Record;
        }

        public readonly void Write(Span<byte> Destination)
        {
            Destination.Slice(0, Size).Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(Destination, EventType);
            if (!IsKey)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Destination.Slice(0x04), PayloadLow);
                BinaryPrimitives.WriteUInt64LittleEndian(Destination.Slice(0x0C), PayloadHigh);
                return;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x04), KeyDown ? 1u : 0u);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x08), RepeatCount);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x0A), VirtualKey);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x0C), ScanCode);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x0E), Character);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x10), ControlKeyState);
        }
    }

    internal enum ConsoleReadResult
    {
        Done,
        NeedInput,
        EndOfInput,
        Yield
    }

    /// <summary>
    /// State shared by every handle onto the guest's one console input buffer and active screen buffer.
    /// </summary>
    public sealed class ConsoleState
    {
        internal const ushort KeyEvent = 0x0001;
        internal const uint EnableProcessedInput = 0x0001;
        internal const uint EnableLineInput = 0x0002;
        internal const uint EnableEchoInput = 0x0004;
        internal const uint EnableVirtualTerminalInput = 0x0200;
        private const uint EnableVirtualTerminalProcessing = 0x0004;

        private const uint RightAltPressed = 0x0001;
        private const uint LeftAltPressed = 0x0002;
        private const uint RightCtrlPressed = 0x0004;
        private const uint LeftCtrlPressed = 0x0008;
        private const uint ShiftPressed = 0x0010;
        private const uint EnhancedKey = 0x0100;

        private const ushort VkBack = 0x08;
        private const ushort VkTab = 0x09;
        private const ushort VkReturn = 0x0D;
        private const ushort VkPause = 0x13;
        private const ushort VkEscape = 0x1B;
        private const ushort VkSpace = 0x20;
        private const ushort VkPrior = 0x21;
        private const ushort VkNext = 0x22;
        private const ushort VkEnd = 0x23;
        private const ushort VkHome = 0x24;
        private const ushort VkLeft = 0x25;
        private const ushort VkUp = 0x26;
        private const ushort VkRight = 0x27;
        private const ushort VkDown = 0x28;
        private const ushort VkInsert = 0x2D;
        private const ushort VkDelete = 0x2E;
        private const ushort VkF1 = 0x70;
        private const ushort VkF4 = 0x73;
        private const ushort VkF5 = 0x74;
        private const ushort VkF12 = 0x7B;

        // conhost: VkKeyScanW(0) on the US layout.
        private const ushort NulVirtualKey = 0x32;
        private const uint NulControlKeyState = ShiftPressed | LeftCtrlPressed;

        private const int MaxLineCharacters = 1 << 16;
        private const int MaxRecordsPerEdit = 1024;

        private static ReadOnlySpan<byte> FunctionKeyCodes => new byte[] { 15, 17, 18, 19, 20, 21, 23, 24 };

        public uint InputMode { get; private set; } = 0x01F7;
        public uint OutputMode = 0x0003;
        public ushort Attributes = 0x0007;
        public ushort CursorX;
        public ushort CursorY;
        public uint CursorSize = 25;
        public bool CursorVisible = true;

        private readonly Queue<ConsoleInputRecord> Records = new Queue<ConsoleInputRecord>();
        private int HeadRepeatsTaken;
        private bool EndDelivered;

        private readonly StringBuilder Line = new StringBuilder();
        private readonly StringBuilder Echo = new StringBuilder();
        private int LineCursor;
        private int LineChangedFrom;
        private bool LineActive;
        private bool LineOverwrite;
        private string PendingText = string.Empty;
        private int PendingTextOffset;
        private byte[] PendingBytes = Array.Empty<byte>();
        private int PendingBytesOffset;

        private enum OutputParse
        {
            Ground,
            Escape,
            CsiStart,
            PrivateParameters
        }

        private bool CursorKeysApplication;
        private OutputParse OutputState;
        private int OutputParameter;
        private bool OutputParameterHasOne;

        public int PendingRecords => Records.Count;

        public bool InputExhausted => EndDelivered && Records.Count == 0;

        public void SetInputMode(BinaryEmulator Instance, uint Mode)
        {
            InputMode = Mode;
            GeneralHelper.HostConsoleInput.SetControlCAsInput((Mode & EnableProcessedInput) == 0);
        }

        // Call under the kernel lock before reading the buffer. The host thread never touches it.
        public void Poll(BinaryEmulator Instance)
        {
            GeneralHelper.HostConsoleInput.EnsureStarted(Instance.WakeSignal);

            bool Ended = GeneralHelper.HostConsoleInput.Ended;
            while (GeneralHelper.HostConsoleInput.TryTake(out ConsoleKeyInfo Key))
                AppendHostKey(Key);

            if (Ended && !EndDelivered)
            {
                EndDelivered = true;
                AppendKeyPress('Z', (char)0x1A, LeftCtrlPressed);
                AppendKeyPress(VkReturn, '\r', 0);
            }
        }

        // Only the wait path calls this, so the request blocks.
        public bool HasInput(BinaryEmulator Instance)
        {
            Task NextInput = GeneralHelper.HostConsoleInput.NextInput;
            Poll(Instance);
            if (Records.Count != 0)
                return true;

            GeneralHelper.HostConsoleInput.Request(true, NextInput);
            return false;
        }

        public void FlushRecords()
        {
            Records.Clear();
            HeadRepeatsTaken = 0;
        }

        public int CopyRecords(Span<byte> Destination, int Count)
        {
            int Copied = 0;
            foreach (ConsoleInputRecord Record in Records)
            {
                if (Copied == Count)
                    break;

                Record.Write(Destination.Slice(Copied++ * ConsoleInputRecord.Size));
            }

            return Copied;
        }

        public void RemoveRecords(int Count)
        {
            for (int i = 0; i < Count && Records.Count != 0; i++)
                Records.Dequeue();

            HeadRepeatsTaken = 0;
        }

        // conhost: with VT input on, a key press is stored as one record per character of its sequence.
        public int WriteRecords(ReadOnlySpan<ConsoleInputRecord> Source, bool Append)
        {
            int Limit = Settings.MemoryBudget.ConsoleInputRecords;
            if (Append)
            {
                int Accepted = 0;
                while (Accepted < Source.Length && AppendRecord(Source[Accepted], Limit))
                    Accepted++;

                return Accepted;
            }

            int Room = Limit - Records.Count;
            if (Room <= 0)
                return 0;

            ConsoleInputRecord[] Existing = Records.ToArray();
            Records.Clear();
            int Prepended = 0;
            while (Prepended < Source.Length && AppendRecord(Source[Prepended], Room))
                Prepended++;

            foreach (ConsoleInputRecord Record in Existing)
                Records.Enqueue(Record);

            HeadRepeatsTaken = 0;
            return Prepended;
        }

        // DECCKM (CSI ? 1 h / l) changes how cursor keys are encoded.
        public void TrackOutput(ReadOnlySpan<byte> Data)
        {
            if ((OutputMode & EnableVirtualTerminalProcessing) == 0)
                return;

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
                                CursorKeysApplication = Value == (byte)'h';

                            OutputState = Value == 0x1B ? OutputParse.Escape : OutputParse.Ground;
                        }
                        break;
                }
            }
        }

        internal ConsoleReadResult Read(BinaryEmulator Instance, Span<byte> Output, bool Unicode, bool ProcessControlZ,
            ReadOnlySpan<char> InitialCharacters, uint WakeupMask, out int Written, out uint EndKeyState)
        {
            Written = 0;
            EndKeyState = 0;

            if (!Unicode && PendingBytesOffset < PendingBytes.Length)
            {
                Written = TakePendingBytes(Output);
                return ConsoleReadResult.Done;
            }

            if (PendingTextOffset < PendingText.Length)
            {
                Written = TakePendingText(Output, Unicode);
                return ConsoleReadResult.Done;
            }

            if ((InputMode & EnableLineInput) == 0)
                return ReadRaw(Output, Unicode, out Written);

            if (!LineActive)
            {
                LineActive = true;
                LineOverwrite = false;
                Line.Clear();
                Line.Append(InitialCharacters);
                LineCursor = Line.Length;
            }

            ConsoleReadResult Edited = EditLine(Instance, WakeupMask, out EndKeyState);
            if (Edited == ConsoleReadResult.NeedInput && InputExhausted)
                return ConsoleReadResult.EndOfInput;

            if (Edited != ConsoleReadResult.Done)
                return Edited;

            if (ProcessControlZ && PendingText.Length != 0 && PendingText[0] == (char)0x1A)
            {
                PendingText = string.Empty;
                PendingTextOffset = 0;
                return ConsoleReadResult.Done;
            }

            Written = TakePendingText(Output, Unicode);
            return ConsoleReadResult.Done;
        }

        private ConsoleReadResult ReadRaw(Span<byte> Output, bool Unicode, out int Written)
        {
            Written = 0;
            Encoding Input = ConsoleServer.HostEncoding;
            Span<byte> Encoded = stackalloc byte[8];

            while (TryPeekKeyDown(out ConsoleInputRecord Key))
            {
                if (Key.Character == '\0' && !IsNulKey(Key))
                {
                    DropHeadRecord();
                    continue;
                }

                int Length;
                if (Unicode)
                {
                    if (Output.Length - Written < 2)
                        break;

                    BinaryPrimitives.WriteUInt16LittleEndian(Output.Slice(Written), Key.Character);
                    Length = 2;
                }
                else
                {
                    Length = EncodeCharacter(Input, Key.Character, Encoded);
                    if (Output.Length - Written < Length)
                        break;

                    Encoded.Slice(0, Length).CopyTo(Output.Slice(Written));
                }

                Written += Length;
                ConsumeKeyDown();
            }

            if (Written != 0)
                return ConsoleReadResult.Done;

            return InputExhausted ? ConsoleReadResult.EndOfInput : ConsoleReadResult.NeedInput;
        }

        // The record budget keeps one read from holding the kernel lock for long.
        private ConsoleReadResult EditLine(BinaryEmulator Instance, uint WakeupMask, out uint EndKeyState)
        {
            EndKeyState = 0;
            bool Processed = (InputMode & EnableProcessedInput) != 0;
            bool EchoInput = (InputMode & EnableEchoInput) != 0;
            int ShownLength = Line.Length;
            int ShownCursor = LineCursor;
            LineChangedFrom = int.MaxValue;

            for (int Budget = MaxRecordsPerEdit; TryPeekKeyDown(out ConsoleInputRecord Key); Budget--)
            {
                if (Budget == 0)
                {
                    RedrawLine(Instance, EchoInput, ShownLength, ShownCursor);
                    return ConsoleReadResult.Yield;
                }

                char Character = Key.Character;
                bool Nul = IsNulKey(Key);
                if (Character == '\0' && !Nul && !(Processed && IsEditKey(Key.VirtualKey)))
                {
                    DropHeadRecord();
                    continue;
                }

                if (Character == '\r')
                {
                    ConsumeKeyDown();
                    EndKeyState = Key.ControlKeyState;
                    RedrawLine(Instance, EchoInput, ShownLength, ShownCursor);
                    CompleteLine(Instance, Processed ? "\r\n" : "\r", EchoInput);
                    return ConsoleReadResult.Done;
                }

                if (Character != '\0' && Character < ' ' && (WakeupMask & (1u << Character)) != 0)
                {
                    ConsumeKeyDown();
                    RedrawLine(Instance, EchoInput, ShownLength, ShownCursor);
                    InsertCharacters(Character, 1);
                    EndKeyState = Key.ControlKeyState;
                    CompleteLine(Instance, string.Empty, false);
                    return ConsoleReadResult.Done;
                }

                int Presses = TakeKeyPresses();
                if (Processed && !Nul && TryEditKey(Key, Presses))
                    continue;

                InsertCharacters(Character, Presses);
            }

            RedrawLine(Instance, EchoInput, ShownLength, ShownCursor);
            return ConsoleReadResult.NeedInput;
        }

        // conhost reads NUL only from the VkKeyScanW(0) record.
        private static bool IsNulKey(in ConsoleInputRecord Key)
        {
            return Key.Character == '\0' && Key.VirtualKey == NulVirtualKey &&
                (Key.ControlKeyState & ShiftPressed) != 0 && (Key.ControlKeyState & (LeftCtrlPressed | RightCtrlPressed)) != 0;
        }

        private static bool IsEditKey(ushort VirtualKey)
        {
            return VirtualKey == VkLeft || VirtualKey == VkRight || VirtualKey == VkHome || VirtualKey == VkEnd ||
                VirtualKey == VkDelete || VirtualKey == VkInsert;
        }

        private bool TryEditKey(in ConsoleInputRecord Key, int Presses)
        {
            if (Key.Character == '\b')
            {
                int Erased = Math.Min(Presses, LineCursor);
                LineCursor -= Erased;
                RemoveRange(LineCursor, Erased);
                return true;
            }

            if (Key.VirtualKey == VkEscape)
            {
                MarkChanged(0);
                Line.Clear();
                LineCursor = 0;
                return true;
            }

            if (Key.Character != '\0')
                return false;

            switch (Key.VirtualKey)
            {
                case VkLeft:
                    LineCursor -= Math.Min(Presses, LineCursor);
                    break;

                case VkRight:
                    LineCursor += Math.Min(Presses, Line.Length - LineCursor);
                    break;

                case VkHome:
                    LineCursor = 0;
                    break;

                case VkEnd:
                    LineCursor = Line.Length;
                    break;

                case VkDelete:
                    RemoveRange(LineCursor, Math.Min(Presses, Line.Length - LineCursor));
                    break;

                case VkInsert:
                    if ((Presses & 1) != 0)
                        LineOverwrite = !LineOverwrite;
                    break;
            }

            return true;
        }

        private void InsertCharacters(char Character, int Count)
        {
            if (LineOverwrite && LineCursor < Line.Length)
            {
                int Replaced = Math.Min(Count, Line.Length - LineCursor);
                MarkChanged(LineCursor);
                for (int i = 0; i < Replaced; i++)
                    Line[LineCursor++] = Character;

                Count -= Replaced;
            }

            int Inserted = Math.Min(Count, MaxLineCharacters - Line.Length);
            if (Inserted <= 0)
                return;

            MarkChanged(LineCursor);
            Line.Insert(LineCursor, Character.ToString(), Inserted);
            LineCursor += Inserted;
        }

        private void RemoveRange(int Index, int Count)
        {
            if (Count <= 0)
                return;

            MarkChanged(Index);
            Line.Remove(Index, Count);
        }

        private void MarkChanged(int Index) => LineChangedFrom = Math.Min(LineChangedFrom, Index);

        private void RedrawLine(BinaryEmulator Instance, bool EchoInput, int ShownLength, int ShownCursor)
        {
            if (!EchoInput)
                return;

            bool Changed = LineChangedFrom != int.MaxValue;
            int From = Changed ? LineChangedFrom : LineCursor;
            Echo.Clear();
            MoveEchoCursor(ShownCursor, From);
            if (Changed)
            {
                AppendLine(From, Line.Length);
                int Removed = ShownLength - Line.Length;
                if (Removed > 0)
                    Echo.Append(' ', Removed).Append('\b', Removed);

                Echo.Append('\b', Line.Length - LineCursor);
            }

            if (Echo.Length != 0)
                ConsoleServer.EchoText(Instance, Echo);
        }

        private void MoveEchoCursor(int From, int To)
        {
            if (From > To)
                Echo.Append('\b', From - To);
            else
                AppendLine(From, To);
        }

        private void AppendLine(int Start, int End)
        {
            for (int i = Start; i < End; i++)
                Echo.Append(Line[i]);
        }

        private void CompleteLine(BinaryEmulator Instance, string Terminator, bool EchoInput)
        {
            if (EchoInput)
            {
                Echo.Clear();
                AppendLine(LineCursor, Line.Length);
                Echo.Append(Terminator);
                ConsoleServer.EchoText(Instance, Echo);
            }

            Line.Append(Terminator);
            PendingText = Line.ToString();
            PendingTextOffset = 0;
            Line.Clear();
            LineCursor = 0;
            LineActive = false;
        }

        private int TakePendingText(Span<byte> Output, bool Unicode)
        {
            if (!Unicode)
            {
                PendingBytes = ConsoleServer.HostEncoding.GetBytes(PendingText, PendingTextOffset, PendingText.Length - PendingTextOffset);
                PendingBytesOffset = 0;
                PendingText = string.Empty;
                PendingTextOffset = 0;
                return TakePendingBytes(Output);
            }

            int Count = Math.Min(PendingText.Length - PendingTextOffset, Output.Length / 2);
            for (int i = 0; i < Count; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(Output.Slice(i * 2), PendingText[PendingTextOffset + i]);

            PendingTextOffset += Count;
            if (PendingTextOffset == PendingText.Length)
            {
                PendingText = string.Empty;
                PendingTextOffset = 0;
            }

            return Count * 2;
        }

        private int TakePendingBytes(Span<byte> Output)
        {
            int Count = Math.Min(PendingBytes.Length - PendingBytesOffset, Output.Length);
            PendingBytes.AsSpan(PendingBytesOffset, Count).CopyTo(Output);
            PendingBytesOffset += Count;
            if (PendingBytesOffset == PendingBytes.Length)
            {
                PendingBytes = Array.Empty<byte>();
                PendingBytesOffset = 0;
            }

            return Count;
        }

        private static int EncodeCharacter(Encoding Input, char Character, Span<byte> Destination)
        {
            if (Character < 0x80)
            {
                Destination[0] = (byte)Character;
                return 1;
            }

            ReadOnlySpan<char> Single = stackalloc char[1] { Character };
            return Input.GetBytes(Single, Destination);
        }

        private bool TryPeekKeyDown(out ConsoleInputRecord Key)
        {
            while (Records.TryPeek(out Key))
            {
                if (Key.IsKey && Key.KeyDown)
                    return true;

                Records.Dequeue();
                HeadRepeatsTaken = 0;
            }

            return false;
        }

        private void DropHeadRecord()
        {
            Records.Dequeue();
            HeadRepeatsTaken = 0;
        }

        private int TakeKeyPresses()
        {
            int Presses = Math.Max((int)Records.Peek().RepeatCount, 1) - HeadRepeatsTaken;
            DropHeadRecord();
            return Presses;
        }

        private void ConsumeKeyDown()
        {
            ConsoleInputRecord Head = Records.Peek();
            if (++HeadRepeatsTaken < Math.Max((int)Head.RepeatCount, 1))
                return;

            Records.Dequeue();
            HeadRepeatsTaken = 0;
        }

        private void AppendHostKey(ConsoleKeyInfo Key)
        {
            uint State = 0;
            if ((Key.Modifiers & ConsoleModifiers.Control) != 0)
                State |= LeftCtrlPressed;
            if ((Key.Modifiers & ConsoleModifiers.Alt) != 0)
                State |= LeftAltPressed;
            if ((Key.Modifiers & ConsoleModifiers.Shift) != 0)
                State |= ShiftPressed;

            ushort VirtualKey = (ushort)Key.Key;
            if ((VirtualKey >= VkPrior && VirtualKey <= VkDown) || VirtualKey == VkInsert || VirtualKey == VkDelete)
                State |= EnhancedKey;

            AppendKeyPress(VirtualKey, Key.KeyChar, State);
        }

        private void AppendKeyPress(ushort VirtualKey, char Character, uint State)
        {
            int Limit = Settings.MemoryBudget.ConsoleInputRecords;
            AppendRecord(ConsoleInputRecord.Key(true, VirtualKey, 0, Character, State), Limit);
            AppendRecord(ConsoleInputRecord.Key(false, VirtualKey, 0, Character, State), Limit);
        }

        private bool AppendRecord(in ConsoleInputRecord Record, int Limit)
        {
            if (Records.Count >= Limit)
                return false;

            if ((InputMode & EnableVirtualTerminalInput) != 0 && Record.IsKey && Record.KeyDown)
            {
                Span<char> Sequence = stackalloc char[8];
                int Length = TranslateKey(Record, Sequence);
                if (Length != 0)
                {
                    for (int i = 0; i < Length; i++)
                    {
                        Records.Enqueue(Sequence[i] == '\0'
                            ? ConsoleInputRecord.Key(true, NulVirtualKey, 0, '\0', NulControlKeyState)
                            : ConsoleInputRecord.Key(true, 0, 0, Sequence[i], 0));
                    }

                    return true;
                }
            }

            Records.Enqueue(Record);
            return true;
        }

        // conhost VT input encoding. Returns 0 when the key has none.
        private int TranslateKey(in ConsoleInputRecord Key, Span<char> Output)
        {
            uint State = Key.ControlKeyState;
            bool Shift = (State & ShiftPressed) != 0;
            bool Alt = (State & (LeftAltPressed | RightAltPressed)) != 0;
            bool Ctrl = (State & (LeftCtrlPressed | RightCtrlPressed)) != 0;
            int Modifier = 1 + (Shift ? 1 : 0) + (Alt ? 2 : 0) + (Ctrl ? 4 : 0);

            switch (Key.VirtualKey)
            {
                case VkUp:
                    return WriteCursorKey('A', Modifier, Output);
                case VkDown:
                    return WriteCursorKey('B', Modifier, Output);
                case VkRight:
                    return WriteCursorKey('C', Modifier, Output);
                case VkLeft:
                    return WriteCursorKey('D', Modifier, Output);
                case VkHome:
                    return WriteCursorKey('H', Modifier, Output);
                case VkEnd:
                    return WriteCursorKey('F', Modifier, Output);
                case VkInsert:
                    return WriteCsi(2, Modifier, '~', Output);
                case VkDelete:
                    return WriteCsi(3, Modifier, '~', Output);
                case VkPrior:
                    return WriteCsi(5, Modifier, '~', Output);
                case VkNext:
                    return WriteCsi(6, Modifier, '~', Output);
                case >= VkF1 and <= VkF4:
                    if (Modifier != 1)
                        return WriteCsi(1, Modifier, (char)('P' + Key.VirtualKey - VkF1), Output);

                    Output[0] = (char)0x1B;
                    Output[1] = 'O';
                    Output[2] = (char)('P' + Key.VirtualKey - VkF1);
                    return 3;
                case >= VkF5 and <= VkF12:
                    return WriteCsi(FunctionKeyCodes[Key.VirtualKey - VkF5], Modifier, '~', Output);
                case VkBack:
                    return WritePrefixed(Alt, Ctrl ? '\b' : (char)0x7F, Output);
                case VkPause:
                    Output[0] = (char)0x1A;
                    return 1;
                case VkTab when Shift && !Ctrl && !Alt:
                    return WriteCsi(0, 1, 'Z', Output);
                case VkSpace when Ctrl:
                    return WritePrefixed(Alt, '\0', Output);
            }

            if (Key.Character == '\0')
                return Ctrl && Key.VirtualKey == '2' ? WritePrefixed(Alt, '\0', Output) : 0;

            return WritePrefixed(Alt && !Ctrl, Key.Character, Output);
        }

        private int WriteCursorKey(char Final, int Modifier, Span<char> Output)
        {
            if (Modifier != 1)
                return WriteCsi(1, Modifier, Final, Output);

            Output[0] = (char)0x1B;
            Output[1] = CursorKeysApplication ? 'O' : '[';
            Output[2] = Final;
            return 3;
        }

        private static int WriteCsi(int Parameter, int Modifier, char Final, Span<char> Output)
        {
            int Length = 0;
            Output[Length++] = (char)0x1B;
            Output[Length++] = '[';
            if (Parameter != 0)
                Length += WriteNumber(Parameter, Output.Slice(Length));

            if (Modifier != 1)
            {
                Output[Length++] = ';';
                Length += WriteNumber(Modifier, Output.Slice(Length));
            }

            Output[Length++] = Final;
            return Length;
        }

        private static int WriteNumber(int Value, Span<char> Output)
        {
            if (Value < 10)
            {
                Output[0] = (char)('0' + Value);
                return 1;
            }

            Output[0] = (char)('0' + Value / 10);
            Output[1] = (char)('0' + Value % 10);
            return 2;
        }

        private static int WritePrefixed(bool Escape, char Character, Span<char> Output)
        {
            if (!Escape)
            {
                Output[0] = Character;
                return 1;
            }

            Output[0] = (char)0x1B;
            Output[1] = Character;
            return 2;
        }
    }

    internal class ConsoleServer : IWinDevice
    {
        public string DeviceName => "\\Device\\ConDrv";

        private const uint IoctlConDrvReadIo = 0x00500004;
        private const uint IoctlConDrvCompleteIo = 0x0050000B;
        private const uint IoctlConDrvReadInput = 0x0050000F;
        private const uint IoctlConDrvWriteOutput = 0x00500013;
        private const uint IoctlConDrvIssueUserIo = 0x00500016;
        private const uint IoctlConDrvSetServerInformation = 0x0050001F;
        private const uint IoctlConDrvGetServerPid = 0x00500023;
        private const uint IoctlConDrvGetDisplayMode = 0x00500027;
        private const uint IoctlConDrvSetDisplayMode = 0x0050002B;

        private const uint ApiGetConsoleCP = 0x01000000;
        private const uint ApiGetConsoleMode = 0x01000001;
        private const uint ApiSetConsoleMode = 0x01000002;
        private const uint ApiGetNumberOfInputEvents = 0x01000003;
        private const uint ApiGetConsoleInput = 0x01000004;
        private const uint ApiReadConsole = 0x01000005;
        private const uint ApiWriteConsole = 0x01000006;
        private const uint ApiGetConsoleLangId = 0x01000008;

        private const uint ApiFillConsoleOutput = 0x02000000;
        private const uint ApiSetConsoleActiveScreenBuffer = 0x02000002;
        private const uint ApiFlushConsoleInputBuffer = 0x02000003;
        private const uint ApiSetConsoleCP = 0x02000004;
        private const uint ApiGetConsoleCursorInfo = 0x02000005;
        private const uint ApiSetConsoleCursorInfo = 0x02000006;
        private const uint ApiGetConsoleScreenBufferInfo = 0x02000007;
        private const uint ApiSetConsoleScreenBufferSize = 0x02000009;
        private const uint ApiSetConsoleCursorPosition = 0x0200000A;
        private const uint ApiGetLargestConsoleWindowSize = 0x0200000B;
        private const uint ApiSetConsoleTextAttribute = 0x0200000D;
        private const uint ApiSetConsoleWindowInfo = 0x0200000E;
        private const uint ApiWriteConsoleInput = 0x02000010;
        private const uint ApiGetConsoleTitle = 0x02000014;
        private const uint ApiSetConsoleTitle = 0x02000015;

        private const int MessageHeaderSize = 8;
        private const int MaximumDescriptorSize = 128;
        private const ushort ConsoleReadNoRemove = 0x0001;
        private const ushort ConsoleReadNoWait = 0x0002;
        private const uint MaxRecordsPerCall = 1 << 16;
        private const uint MaxReadBytes = 1 << 16;
        private const uint FillAnsiCharacter = 1;
        private const uint FillUnicodeCharacter = 2;

        private const ushort DefaultBufferWidth = 120;
        private const ushort DefaultBufferHeight = 30;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        public static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            switch (IOCTL)
            {
                case IoctlConDrvIssueUserIo:
                    return HandleIssueUserIo(ref Data, Instance);

                case IoctlConDrvGetServerPid:
                    if (Data.OutputBuffer != null && Data.OutputLength >= 4)
                    {
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer, Instance.WinHelper.PID);
                        Data.Information = 4;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case IoctlConDrvGetDisplayMode:
                    if (Data.OutputBuffer != null && Data.OutputLength >= 4)
                    {
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.OutputBuffer, 0);
                        Data.Information = 4;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case IoctlConDrvReadIo:
                case IoctlConDrvCompleteIo:
                case IoctlConDrvReadInput:
                case IoctlConDrvWriteOutput:
                case IoctlConDrvSetServerInformation:
                case IoctlConDrvSetDisplayMode:
                default:
                    if (Data.OutputBuffer != null && Data.OutputLength > 0)
                        Array.Clear(Data.OutputBuffer, 0, (int)Data.OutputLength);
                    return NTSTATUS.STATUS_SUCCESS;
            }
        }

        private static NTSTATUS HandleIssueUserIo(ref DeviceData Data, BinaryEmulator Instance)
        {
            UserIoRequest Request = new UserIoRequest(Instance, in Data);
            if (!Request.Valid)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Request.TryGetBuffer(0, out uint MessageSize, out ulong MessageAddress) || MessageSize < MessageHeaderSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Message = stackalloc byte[MessageHeaderSize];
            if (!Instance.ReadMemory(MessageAddress, Message, MessageHeaderSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint ApiNumber = BinaryPrimitives.ReadUInt32LittleEndian(Message);
            uint DescriptorSize = BinaryPrimitives.ReadUInt32LittleEndian(Message.Slice(4));
            if (DescriptorSize > MaximumDescriptorSize || DescriptorSize > MessageSize - MessageHeaderSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Descriptor = stackalloc byte[MaximumDescriptorSize];
            Descriptor.Clear();
            Span<byte> Used = Descriptor.Slice(0, (int)DescriptorSize);
            if (DescriptorSize != 0 && !Instance.ReadMemory(MessageAddress + MessageHeaderSize, Used, DescriptorSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile Target = ResolveTarget(Instance, Request.Client, Data.File);
            NTSTATUS Status = Dispatch(Instance, Target, ApiNumber, Used, in Request);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Request.TryGetBuffer(Request.InputCount, out uint ReplySize, out ulong ReplyAddress) && ReplySize != 0)
            {
                uint ToWrite = Math.Min(ReplySize, DescriptorSize);
                if (ToWrite != 0 && !Instance.WriteMemory(ReplyAddress, Descriptor.Slice(0, (int)ToWrite)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static WinFile ResolveTarget(BinaryEmulator Instance, ulong Client, WinFile Issued)
        {
            if (Client == 0)
                return Issued;

            return Instance.WinHelper.GetFileByHandle(Client, AccessMask.GiveTemp);
        }

        private static NTSTATUS Dispatch(BinaryEmulator Instance, WinFile Target, uint ApiNumber, Span<byte> Descriptor, in UserIoRequest Request)
        {
            ConsoleObjectKind Kind = Target != null ? Target.ConsoleKind : ConsoleObjectKind.None;
            ConsoleState State = Instance.WinHelper.ConsoleState;

            switch (ApiNumber)
            {
                case ApiGetConsoleMode:
                    if (Descriptor.Length < 4)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                    if (Kind == ConsoleObjectKind.Input)
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, State.InputMode);
                    else if (Kind == ConsoleObjectKind.Output)
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, State.OutputMode);
                    else
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiSetConsoleMode:
                    if (Descriptor.Length < 4)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                    if (Kind == ConsoleObjectKind.Input)
                        State.SetInputMode(Instance, BinaryPrimitives.ReadUInt32LittleEndian(Descriptor));
                    else if (Kind == ConsoleObjectKind.Output)
                        State.OutputMode = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor);
                    else
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetNumberOfInputEvents:
                    if (Kind != ConsoleObjectKind.Input)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    Task NextInput = GeneralHelper.HostConsoleInput.NextInput;
                    State.Poll(Instance);
                    if (State.PendingRecords == 0)
                        GeneralHelper.HostConsoleInput.Request(false, NextInput);
                    if (Descriptor.Length >= 4)
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, (uint)State.PendingRecords);
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiFlushConsoleInputBuffer:
                    if (Kind != ConsoleObjectKind.Input)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    State.FlushRecords();
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleInput:
                    if (Kind != ConsoleObjectKind.Input)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return GetConsoleInput(Instance, Descriptor, in Request, State);

                case ApiWriteConsoleInput:
                    if (Kind != ConsoleObjectKind.Input)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return WriteConsoleInput(Instance, Descriptor, in Request, State);

                case ApiReadConsole:
                    if (Kind != ConsoleObjectKind.Input)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return ReadConsole(Instance, Descriptor, in Request, State);

                case ApiWriteConsole:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return WriteConsole(Instance, Descriptor, in Request);

                case ApiGetConsoleCP:
                    if (Descriptor.Length >= 4)
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, HostCodePage);
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiSetConsoleCP:
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleLangId:
                    if (Descriptor.Length >= 2)
                        BinaryPrimitives.WriteUInt16LittleEndian(Descriptor, 0x0409);
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleScreenBufferInfo:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    WriteScreenBufferInfo(Descriptor, State);
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetLargestConsoleWindowSize:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    if (Descriptor.Length >= 4)
                    {
                        ReadHostGeometry(out ushort Width, out ushort Height, out _, out _);
                        ReadHostWindow(Width, Height, out _, out _, out _, out _, out ushort LargestWidth, out ushort LargestHeight);
                        WriteCoord(Descriptor, LargestWidth, LargestHeight);
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleCursorInfo:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    if (Descriptor.Length >= 8)
                    {
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, State.CursorSize);
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor.Slice(4), State.CursorVisible ? 1u : 0u);
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiSetConsoleCursorInfo:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    if (Descriptor.Length >= 8)
                    {
                        State.CursorSize = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor);
                        State.CursorVisible = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(4)) != 0;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiSetConsoleCursorPosition:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    if (Descriptor.Length >= 4)
                    {
                        State.CursorX = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor);
                        State.CursorY = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(2));
                        MoveHostCursor(State.CursorX, State.CursorY);
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiSetConsoleTextAttribute:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    if (Descriptor.Length >= 2)
                        State.Attributes = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor);
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiFillConsoleOutput:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return FillConsoleOutput(Instance, Descriptor);

                case ApiSetConsoleActiveScreenBuffer:
                case ApiSetConsoleScreenBufferSize:
                case ApiSetConsoleWindowInfo:
                    if (Kind != ConsoleObjectKind.Output)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleTitle:
                    if (Descriptor.Length >= 4)
                        BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiSetConsoleTitle:
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return NTSTATUS.STATUS_SUCCESS;
            }
        }

        private static NTSTATUS WriteConsole(BinaryEmulator Instance, Span<byte> Descriptor, in UserIoRequest Request)
        {
            if (Descriptor.Length < 5)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Request.InputCount < 2 || !Request.TryGetBuffer(1, out uint TextSize, out ulong TextAddress))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (TextSize == 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Unicode = Descriptor[4] != 0;
            uint Total = Unicode ? TextSize & ~1u : TextSize;
            Encoding Output = HostEncoding;
            Encoder Split = Unicode && Total > NtReadFile.IoChunkBytes ? Output.GetEncoder() : null;

            for (uint Done = 0; Done < Total;)
            {
                uint Step = Math.Min(Total - Done, (uint)NtReadFile.IoChunkBytes);
                Span<byte> Text = Instance.WinHelper.ReadMemorySpan(TextAddress + Done, Step);
                if (Text.IsEmpty)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Done += Step;
                if (!Unicode)
                {
                    Instance.WinHelper.ConsoleState.TrackOutput(Text);
                    GeneralHelper.ConsoleWrite(Text, Instance.Settings.ConsoleOutputMode);
                    continue;
                }

                ReadOnlySpan<char> Characters = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(Text);
                byte[] Encoded = ArrayPool<byte>.Shared.Rent(Output.GetMaxByteCount(Characters.Length));
                try
                {
                    int Written = Split != null ? Split.GetBytes(Characters, Encoded, Done == Total) : Output.GetBytes(Characters, Encoded);
                    Instance.WinHelper.ConsoleState.TrackOutput(Encoded.AsSpan(0, Written));
                    GeneralHelper.ConsoleWrite(Encoded.AsSpan(0, Written), Instance.Settings.ConsoleOutputMode);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(Encoded);
                }
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, TextSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReadConsole(BinaryEmulator Instance, Span<byte> Descriptor, in UserIoRequest Request, ConsoleState State)
        {
            if (Descriptor.Length < 20)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Request.TryGetBuffer(Request.InputCount + 1, out uint Capacity, out ulong Address) || Capacity == 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor.Slice(16), 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Unicode = Descriptor[0] != 0;
            bool ProcessControlZ = Descriptor[1] != 0;
            uint InitialBytes = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(4));
            uint WakeupMask = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(8));

            char[] Initial = null;
            int InitialCount = 0;
            try
            {
                if (Unicode && InitialBytes >= 2 && InitialBytes <= Math.Min(Capacity, MaxReadBytes) &&
                    Request.TryGetBuffer(2, out uint InitialSize, out ulong InitialAddress) && InitialSize >= InitialBytes)
                {
                    InitialCount = (int)(InitialBytes / 2);
                    Initial = ArrayPool<char>.Shared.Rent(InitialCount);
                    if (!Instance.ReadMemory(InitialAddress, System.Runtime.InteropServices.MemoryMarshal.AsBytes(Initial.AsSpan(0, InitialCount))))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                Task NextInput = GeneralHelper.HostConsoleInput.NextInput;
                State.Poll(Instance);

                Span<byte> Output = Instance.WinHelper.Shared.GetSpan(Math.Min(Capacity, MaxReadBytes));
                ConsoleReadResult Result = State.Read(Instance, Output, Unicode, ProcessControlZ,
                    Initial != null ? Initial.AsSpan(0, InitialCount) : ReadOnlySpan<char>.Empty, WakeupMask, out int Written, out uint EndKeyState);
                if (Result == ConsoleReadResult.NeedInput || Result == ConsoleReadResult.Yield)
                {
                    WinPendingIo Io = Request.SyncIo(Instance);
                    return ParkRead(Instance, Result, NextInput, in Io);
                }

                if (Written != 0 && !Instance.WriteMemory(Address, Output.Slice(0, Written)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor.Slice(12), EndKeyState);
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor.Slice(16), (uint)Written);
                return NTSTATUS.STATUS_SUCCESS;
            }
            finally
            {
                if (Initial != null)
                    ArrayPool<char>.Shared.Return(Initial);
            }
        }

        // conhost: an ANSI ReadConsole where a line that starts with Ctrl+Z is end of file.
        internal static NTSTATUS ReadFile(BinaryEmulator Instance, in WinPendingIo Io, ulong BufferPtr, uint Length)
        {
            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, Io.IoStatusBlock, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ConsoleState State = Instance.WinHelper.ConsoleState;
            Task NextInput = GeneralHelper.HostConsoleInput.NextInput;
            State.Poll(Instance);

            Span<byte> Output = Instance.WinHelper.Shared.GetSpan(Math.Min(Length, MaxReadBytes));
            ConsoleReadResult Result = State.Read(Instance, Output, false, true, ReadOnlySpan<char>.Empty, 0, out int Written, out _);
            if (Result == ConsoleReadResult.NeedInput || Result == ConsoleReadResult.Yield)
                return ParkRead(Instance, Result, NextInput, in Io);

            if (Written != 0 && !Instance.WriteMemory(BufferPtr, Output.Slice(0, Written)))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, Io.IoStatusBlock, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, Io.IoStatusBlock, NTSTATUS.STATUS_SUCCESS, (ulong)Written);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS GetConsoleInput(BinaryEmulator Instance, Span<byte> Descriptor, in UserIoRequest Request, ConsoleState State)
        {
            if (Descriptor.Length < 8)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ushort Flags = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(4));

            if (!Request.TryGetBuffer(Request.InputCount + 1, out uint Size, out ulong Address) || Size < ConsoleInputRecord.Size)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Task NextInput = GeneralHelper.HostConsoleInput.NextInput;
            State.Poll(Instance);

            if (State.PendingRecords == 0)
            {
                if ((Flags & ConsoleReadNoWait) == 0)
                {
                    if (State.InputExhausted)
                        return NTSTATUS.STATUS_END_OF_FILE;

                    WinPendingIo Io = Request.SyncIo(Instance);
                    return ParkUntilInput(Instance, NextInput, in Io);
                }

                GeneralHelper.HostConsoleInput.Request(false, NextInput);
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Count = Math.Min(Math.Min(Size / ConsoleInputRecord.Size, (uint)State.PendingRecords), MaxRecordsPerCall);
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Count * ConsoleInputRecord.Size);
            int Copied = State.CopyRecords(Buffer, (int)Count);

            if (!Instance.WriteMemory(Address, Buffer.Slice(0, Copied * ConsoleInputRecord.Size)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Flags & ConsoleReadNoRemove) == 0)
                State.RemoveRecords(Copied);

            BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, (uint)Copied);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS WriteConsoleInput(BinaryEmulator Instance, Span<byte> Descriptor, in UserIoRequest Request, ConsoleState State)
        {
            if (Descriptor.Length < 8)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool Unicode = Descriptor[4] != 0;
            bool Append = Descriptor[5] != 0;

            if (!Request.TryGetBuffer(1, out uint Size, out ulong Address) || Size < ConsoleInputRecord.Size)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Count = (int)Math.Min(Size / ConsoleInputRecord.Size, MaxRecordsPerCall);
            Span<byte> Raw = Instance.WinHelper.ReadMemorySpan(Address, (uint)(Count * ConsoleInputRecord.Size));
            if (Raw.IsEmpty)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ConsoleInputRecord[] Parsed = ArrayPool<ConsoleInputRecord>.Shared.Rent(Count);
            try
            {
                for (int i = 0; i < Count; i++)
                {
                    ConsoleInputRecord Record = ConsoleInputRecord.Read(Raw.Slice(i * ConsoleInputRecord.Size));
                    if (!Unicode && Record.IsKey)
                        Record.Character = DecodeAnsiCharacter((byte)Record.Character);

                    Parsed[i] = Record;
                }

                State.Poll(Instance);
                int Accepted = State.WriteRecords(Parsed.AsSpan(0, Count), Append);
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, (uint)Accepted);
                if (Accepted != 0)
                    GeneralHelper.HostConsoleInput.SignalInput();
            }
            finally
            {
                ArrayPool<ConsoleInputRecord>.Shared.Return(Parsed);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static char DecodeAnsiCharacter(byte Value)
        {
            if (Value < 0x80)
                return (char)Value;

            ReadOnlySpan<byte> Single = stackalloc byte[1] { Value };
            Span<char> Decoded = stackalloc char[2];
            return HostEncoding.GetChars(Single, Decoded) != 0 ? Decoded[0] : '\0';
        }

        private static NTSTATUS ParkUntilInput(BinaryEmulator Instance, Task NextInput, in WinPendingIo Io)
        {
            GeneralHelper.HostConsoleInput.Request(true, NextInput);
            return Instance.WinHelper.TryRetrySyscallWhenDone(NextInput, Io) ? NTSTATUS.STATUS_PENDING : NTSTATUS.STATUS_UNSUCCESSFUL;
        }

        private static NTSTATUS ParkRead(BinaryEmulator Instance, ConsoleReadResult Result, Task NextInput, in WinPendingIo Io)
        {
            if (Result == ConsoleReadResult.NeedInput)
                return ParkUntilInput(Instance, NextInput, in Io);

            return Instance.WinHelper.TryRetrySyscallAfterSlice(1, Io) ? NTSTATUS.STATUS_PENDING : NTSTATUS.STATUS_UNSUCCESSFUL;
        }

        internal static void EchoText(BinaryEmulator Instance, StringBuilder Text)
        {
            byte[] Encoded = HostEncoding.GetBytes(Text.ToString());
            GeneralHelper.ConsoleWrite(Encoded, Instance.Settings.ConsoleOutputMode);
        }

        internal static Encoding HostEncoding
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

        private static uint HostCodePage => (uint)HostEncoding.CodePage;

        private static void WriteScreenBufferInfo(Span<byte> Descriptor, ConsoleState State)
        {
            if (Descriptor.Length < 0x19)
                return;

            ReadHostGeometry(out ushort Width, out ushort Height, out ushort CursorX, out ushort CursorY);
            if (!HostConsoleUsable)
            {
                CursorX = State.CursorX;
                CursorY = State.CursorY;
            }

            ReadHostWindow(Width, Height, out ushort Left, out ushort Top, out ushort WindowWidth, out ushort WindowHeight, out ushort LargestWidth, out ushort LargestHeight);

            WriteCoord(Descriptor, Width, Height);
            WriteCoord(Descriptor.Slice(0x04), CursorX, CursorY);
            WriteCoord(Descriptor.Slice(0x08), Left, Top);
            BinaryPrimitives.WriteUInt16LittleEndian(Descriptor.Slice(0x0C), State.Attributes);
            WriteCoord(Descriptor.Slice(0x0E), WindowWidth, WindowHeight);
            WriteCoord(Descriptor.Slice(0x12), Math.Min(Width, LargestWidth), Math.Min(Height, LargestHeight));
            BinaryPrimitives.WriteUInt16LittleEndian(Descriptor.Slice(0x16), State.Attributes);
            Descriptor[0x18] = 0;
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

        /// <summary>
        /// The guest's screen buffer is the host console, so a program that positions its cursor from the
        /// reported geometry only lands where it means to if both come from the same place.
        /// </summary>
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

        private static bool HostConsoleUsable => !Console.IsOutputRedirected;

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

        private static NTSTATUS FillConsoleOutput(BinaryEmulator Instance, Span<byte> Descriptor)
        {
            if (Descriptor.Length < 16)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint ElementType = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(0x04));
            if (ElementType != FillAnsiCharacter && ElementType != FillUnicodeCharacter)
                return NTSTATUS.STATUS_SUCCESS;

            uint Length = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor.Slice(0x0C));
            if (Length == 0 || !HostConsoleUsable)
                return NTSTATUS.STATUS_SUCCESS;

            ushort X = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor);
            ushort Y = BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(0x02));
            char Element = (char)BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(0x08));

            try
            {
                int SavedX = Console.CursorLeft;
                int SavedY = Console.CursorTop;
                int Cells = (int)Math.Min(Length, (uint)(Console.BufferWidth * Console.BufferHeight));

                MoveHostCursor(X, Y);
                WriteRepeated(Instance, Element, Cells);
                MoveHostCursor(SavedX, SavedY);
            }
            catch (IOException)
            {
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteRepeated(BinaryEmulator Instance, char Element, int Count)
        {
            Encoding Output = HostEncoding;
            int Stride = Output.GetMaxByteCount(1);
            byte[] Buffer = ArrayPool<byte>.Shared.Rent(Count * Stride);
            try
            {
                Span<char> Single = stackalloc char[1] { Element };
                int Written = 0;
                for (int i = 0; i < Count; i++)
                    Written += Output.GetBytes(Single, Buffer.AsSpan(Written));

                GeneralHelper.ConsoleWrite(Buffer.AsSpan(0, Written), Instance.Settings.ConsoleOutputMode);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        private static void WriteCoord(Span<byte> Destination, ushort X, ushort Y)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Destination, X);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(2), Y);
        }

        /// <summary>
        /// A parsed CD_USER_DEFINED_IO header plus its CD_IO_BUFFER table.
        /// </summary>
        private readonly ref struct UserIoRequest
        {
            private const int TableOffset = 0x10;
            private const int Stride = 0x10;

            private readonly ReadOnlySpan<byte> Raw;
            private readonly DeviceData Origin;

            public readonly ulong Client;
            public readonly uint InputCount;
            public readonly uint OutputCount;
            public readonly bool Valid;

            public UserIoRequest(BinaryEmulator Instance, in DeviceData Data)
            {
                Client = 0;
                InputCount = 0;
                OutputCount = 0;
                Valid = false;
                Raw = default;
                Origin = Data;

                byte[] Buffer = Data.InputBuffer;
                uint Length = Data.InputLength;
                if (Buffer == null || Length < TableOffset || Buffer.Length < Length)
                    return;

                ReadOnlySpan<byte> Header = Buffer.AsSpan(0, (int)Length);
                Client = BinaryPrimitives.ReadUInt64LittleEndian(Header);
                InputCount = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x08));
                OutputCount = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x0C));

                if (InputCount == 0 || OutputCount == 0)
                    return;

                long Required = TableOffset + (long)(InputCount + OutputCount) * Stride;
                if (Length < Required)
                    return;

                Raw = Header;
                Valid = true;
            }

            public WinPendingIo SyncIo(BinaryEmulator Instance) =>
                new WinPendingIo(in Origin, Instance.CurrentThreadId, Instance.WinHelper.GetEventByHandle(Origin.EventHandle, AccessMask.GiveTemp));

            public bool TryGetBuffer(uint Index, out uint Size, out ulong Address)
            {
                Size = 0;
                Address = 0;

                if (!Valid || Index >= InputCount + OutputCount)
                    return false;

                ReadOnlySpan<byte> Entry = Raw.Slice(TableOffset + (int)Index * Stride, Stride);
                Size = BinaryPrimitives.ReadUInt32LittleEndian(Entry);
                Address = BinaryPrimitives.ReadUInt64LittleEndian(Entry.Slice(0x08));
                return Address != 0;
            }
        }
    }
}
