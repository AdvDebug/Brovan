using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    public struct ConsoleKeyRecord
    {
        public ushort VirtualKey;
        public char Character;
        public uint ControlKeyState;
        public bool KeyDown;
    }

    /// <summary>
    /// State shared by every handle onto the guest's one console input buffer and active screen buffer.
    /// </summary>
    public sealed class ConsoleState
    {
        private const uint LeftCtrlPressed = 0x0008;
        private const uint LeftAltPressed = 0x0002;
        private const uint ShiftPressed = 0x0010;

        public uint InputMode = 0x01F7;
        public uint OutputMode = 0x0003;
        public ushort Attributes = 0x0007;
        public ushort CursorX;
        public ushort CursorY;
        public uint CursorSize = 25;
        public bool CursorVisible = true;

        private readonly Queue<ConsoleKeyRecord> Records = new Queue<ConsoleKeyRecord>();
        private bool Ended;

        public int PendingRecords => Records.Count;

        public void FlushRecords() => Records.Clear();

        public bool TryTakeRecord(out ConsoleKeyRecord Record) => Records.TryDequeue(out Record);

        public Queue<ConsoleKeyRecord>.Enumerator PeekRecords() => Records.GetEnumerator();

        /// <summary>
        /// Turns host input into the key events a console reader expects. A live host console is read one
        /// keystroke at a time with echo suppressed, because the guest draws its own line editor. a redirected
        /// host stream has no keystrokes to read, so whole lines are expanded into synthetic ones.
        /// </summary>
        /// <param name="Blocking">Whether to wait for input that has not arrived yet.</param>
        /// <returns>False once the host input has ended and the end-of-file key has already been delivered.</returns>
        public bool FillFromHost(bool Blocking)
        {
            if (Ended)
                return false;

            if (!Console.IsInputRedirected)
            {
                bool Added = false;
                while (Console.KeyAvailable)
                {
                    Enqueue(Console.ReadKey(true));
                    Added = true;
                }

                if (!Added && Blocking)
                    Enqueue(Console.ReadKey(true));

                return true;
            }

            if (!Blocking)
                return true;

            string Line = Console.ReadLine();
            if (Line == null)
            {
                Ended = true;
                Enqueue((char)0x1A, 0x5A, LeftCtrlPressed);
                Enqueue('\r', 0x0D, 0);
                return true;
            }

            for (int i = 0; i < Line.Length; i++)
                Enqueue(Line[i], VirtualKeyFor(Line[i]), 0);

            Enqueue('\r', 0x0D, 0);
            return true;
        }

        private void Enqueue(ConsoleKeyInfo Key)
        {
            uint ControlKeyState = 0;
            if ((Key.Modifiers & ConsoleModifiers.Control) != 0)
                ControlKeyState |= LeftCtrlPressed;
            if ((Key.Modifiers & ConsoleModifiers.Alt) != 0)
                ControlKeyState |= LeftAltPressed;
            if ((Key.Modifiers & ConsoleModifiers.Shift) != 0)
                ControlKeyState |= ShiftPressed;

            Enqueue(Key.KeyChar, (ushort)Key.Key, ControlKeyState);
        }

        private void Enqueue(char Character, ushort VirtualKey, uint ControlKeyState)
        {
            Records.Enqueue(new ConsoleKeyRecord { Character = Character, VirtualKey = VirtualKey, ControlKeyState = ControlKeyState, KeyDown = true });
            Records.Enqueue(new ConsoleKeyRecord { Character = Character, VirtualKey = VirtualKey, ControlKeyState = ControlKeyState, KeyDown = false });
        }

        private static ushort VirtualKeyFor(char Character)
        {
            if (Character >= 'a' && Character <= 'z')
                return (ushort)(Character - 'a' + 'A');

            if ((Character >= 'A' && Character <= 'Z') || (Character >= '0' && Character <= '9'))
                return Character;

            switch (Character)
            {
                case '\r':
                case '\n': return 0x0D;
                case '\b': return 0x08;
                case '\t': return 0x09;
                case (char)0x1B: return 0x1B;
                case ' ': return 0x20;
                default: return 0;
            }
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
        private const uint ApiGetConsoleTitle = 0x02000014;
        private const uint ApiSetConsoleTitle = 0x02000015;

        private const int MessageHeaderSize = 8;
        private const int MaximumDescriptorSize = 128;
        private const uint InputRecordSize = 20;
        private const ushort KeyEvent = 0x0001;
        private const ushort ConsoleInputPeek = 0x0002;
        private const uint EnableEchoInput = 0x0004;
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
            UserIoRequest Request = new UserIoRequest(Instance, Data.InputBuffer, Data.InputLength);
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
                if (ToWrite != 0)
                    Instance.WriteMemory(ReplyAddress, Descriptor.Slice(0, (int)ToWrite));
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        /// <summary>
        /// Resolves the console object an API call acts on.
        /// </summary>
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
                        State.InputMode = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor);
                    else if (Kind == ConsoleObjectKind.Output)
                        State.OutputMode = BinaryPrimitives.ReadUInt32LittleEndian(Descriptor);
                    else
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetNumberOfInputEvents:
                    if (Kind != ConsoleObjectKind.Input)
                        return NTSTATUS.STATUS_INVALID_HANDLE;
                    State.FillFromHost(false);
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
                        WriteCoord(Descriptor, Width, Height);
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
            Span<byte> Text = Instance.WinHelper.ReadMemorySpan(TextAddress, TextSize);
            if (Text.IsEmpty)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Unicode)
            {
                GeneralHelper.ConsoleWrite(Text, Instance.Settings.ConsoleOutputMode);
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, TextSize);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ReadOnlySpan<char> Characters = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(Text.Slice(0, (int)(TextSize & ~1u)));
            Encoding Output = HostEncoding;
            byte[] Encoded = ArrayPool<byte>.Shared.Rent(Output.GetMaxByteCount(Characters.Length));
            try
            {
                int Written = Output.GetBytes(Characters, Encoded);
                GeneralHelper.ConsoleWrite(Encoded.AsSpan(0, Written), Instance.Settings.ConsoleOutputMode);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Encoded);
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
            int MaximumCharacters = (int)(Unicode ? Capacity / 2 : Capacity);
            if (MaximumCharacters == 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor.Slice(16), 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Echo = !Console.IsInputRedirected && (State.InputMode & EnableEchoInput) != 0;
            char[] Line = ArrayPool<char>.Shared.Rent(MaximumCharacters);
            int Count = 0;
            try
            {
                while (Count < MaximumCharacters)
                {
                    if (State.PendingRecords == 0 && !State.FillFromHost(true))
                        break;

                    if (!State.TryTakeRecord(out ConsoleKeyRecord Record))
                        break;

                    if (!Record.KeyDown || Record.Character == '\0')
                        continue;

                    if (Record.Character == '\r')
                    {
                        Line[Count++] = '\r';
                        if (Count < MaximumCharacters)
                            Line[Count++] = '\n';
                        if (Echo)
                            EchoCharacters(Instance, "\r\n");
                        break;
                    }

                    if (Record.Character == '\b')
                    {
                        if (Count == 0)
                            continue;

                        Count--;
                        if (Echo)
                            EchoCharacters(Instance, "\b \b");
                        continue;
                    }

                    Line[Count++] = Record.Character;
                    if (Echo)
                        EchoCharacters(Instance, Record.Character.ToString());
                }

                Encoding Input = Unicode ? Encoding.Unicode : HostEncoding;
                int Written = 0;
                if (Count != 0)
                {
                    byte[] Encoded = ArrayPool<byte>.Shared.Rent(Input.GetMaxByteCount(Count));
                    try
                    {
                        Written = Input.GetBytes(Line.AsSpan(0, Count), Encoded);
                        if (Written > Capacity)
                            Written = (int)Capacity;

                        if (Written != 0 && !Instance.WriteMemory(Address, Encoded.AsSpan(0, Written)))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(Encoded);
                    }
                }

                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor.Slice(16), (uint)Written);
            }
            finally
            {
                ArrayPool<char>.Shared.Return(Line);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS GetConsoleInput(BinaryEmulator Instance, Span<byte> Descriptor, in UserIoRequest Request, ConsoleState State)
        {
            if (Descriptor.Length < 8)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool Peek = (BinaryPrimitives.ReadUInt16LittleEndian(Descriptor.Slice(4)) & ConsoleInputPeek) != 0;

            if (!Request.TryGetBuffer(Request.InputCount + 1, out uint Size, out ulong Address) || Size < InputRecordSize)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (State.PendingRecords == 0 && !State.FillFromHost(!Peek))
                return NTSTATUS.STATUS_END_OF_FILE;

            if (State.PendingRecords == 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Count = Math.Min(Size / InputRecordSize, (uint)State.PendingRecords);
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Count * InputRecordSize);
            Buffer.Clear();

            if (Peek)
            {
                uint Index = 0;
                Queue<ConsoleKeyRecord>.Enumerator Pending = State.PeekRecords();
                while (Index < Count && Pending.MoveNext())
                    WriteInputRecord(Buffer.Slice((int)(Index++ * InputRecordSize)), Pending.Current);
            }
            else
            {
                for (uint Index = 0; Index < Count; Index++)
                {
                    State.TryTakeRecord(out ConsoleKeyRecord Record);
                    WriteInputRecord(Buffer.Slice((int)(Index * InputRecordSize)), Record);
                }
            }

            if (!Instance.WriteMemory(Address, Buffer.Slice(0, (int)(Count * InputRecordSize))))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt32LittleEndian(Descriptor, Count);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void EchoCharacters(BinaryEmulator Instance, string Text)
        {
            Encoding Output = HostEncoding;
            Span<byte> Encoded = stackalloc byte[16];
            int Written = Output.GetBytes(Text.AsSpan(), Encoded);
            GeneralHelper.ConsoleWrite(Encoded.Slice(0, Written), Instance.Settings.ConsoleOutputMode);
        }

        private static void WriteInputRecord(Span<byte> Destination, ConsoleKeyRecord Record)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Destination, KeyEvent);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x04), Record.KeyDown ? 1u : 0u);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x08), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x0A), Record.VirtualKey);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x0C), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(Destination.Slice(0x0E), Record.Character);
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0x10), Record.ControlKeyState);
        }

        private static Encoding HostEncoding
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

            WriteCoord(Descriptor, Width, Height);
            WriteCoord(Descriptor.Slice(0x04), CursorX, CursorY);
            WriteCoord(Descriptor.Slice(0x08), 0, 0);
            BinaryPrimitives.WriteUInt16LittleEndian(Descriptor.Slice(0x0C), State.Attributes);
            WriteCoord(Descriptor.Slice(0x0E), Width, Height);
            WriteCoord(Descriptor.Slice(0x12), Width, Height);
            BinaryPrimitives.WriteUInt16LittleEndian(Descriptor.Slice(0x16), State.Attributes);
            Descriptor[0x18] = 0;
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

            public readonly ulong Client;
            public readonly uint InputCount;
            public readonly uint OutputCount;
            public readonly bool Valid;

            public UserIoRequest(BinaryEmulator Instance, byte[] Buffer, uint Length)
            {
                Client = 0;
                InputCount = 0;
                OutputCount = 0;
                Valid = false;
                Raw = default;

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
