using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal readonly struct Win32kRawDevice
    {
        public readonly ulong Handle;
        public readonly uint Type;
        public readonly string Name;

        public Win32kRawDevice(ulong Handle, uint Type, string Name)
        {
            this.Handle = Handle;
            this.Type = Type;
            this.Name = Name;
        }
    }

    internal static class Win32kRawInput
    {
        internal const uint RimTypeMouse = 0;
        internal const uint RimTypeKeyboard = 1;
        internal const uint RimTypeHid = 2;

        internal const ushort UsagePageGeneric = 0x01;
        internal const ushort UsageMouse = 0x02;
        internal const ushort UsageKeyboard = 0x06;

        internal const uint RIDEV_REMOVE = 0x00000001;
        internal const uint RIDEV_EXCLUDE = 0x00000010;
        internal const uint RIDEV_PAGEONLY = 0x00000020;
        internal const uint RIDEV_NOLEGACY = 0x00000030;
        internal const uint RIDEV_INPUTSINK = 0x00000100;
        internal const uint RIDEV_EXINPUTSINK = 0x00001000;

        internal const uint RID_INPUT = 0x10000003;
        internal const uint RID_HEADER = 0x10000005;

        internal const uint RIDI_PREPARSEDDATA = 0x20000005;
        internal const uint RIDI_DEVICENAME = 0x20000007;
        internal const uint RIDI_DEVICEINFO = 0x2000000B;

        internal const uint DeviceInfoSize = 32;

        private const ushort RI_MOUSE_LEFT_BUTTON_DOWN = 0x0001;
        private const ushort RI_MOUSE_LEFT_BUTTON_UP = 0x0002;
        private const ushort RI_MOUSE_RIGHT_BUTTON_DOWN = 0x0004;
        private const ushort RI_MOUSE_RIGHT_BUTTON_UP = 0x0008;

        private const ushort MOUSE_MOVE_RELATIVE = 0x0000;

        private const ushort RI_KEY_BREAK = 0x01;
        private const ushort RI_KEY_E0 = 0x02;

        private const uint HeaderSize64 = 24;
        private const uint HeaderSize32 = 16;
        private const uint MousePayloadSize = 24;
        private const uint KeyboardPayloadSize = 16;

        private const int RecordSlots = 128;
        private const uint MinConfineExtent = 64;

        private static readonly Win32kRawDevice[] Devices =
        {
            new Win32kRawDevice(0x00010001, RimTypeMouse, @"\\?\HID#VID_046D&PID_C077&MI_00#7&1a2b3c4d&0&0000#{378de44c-56ef-11d1-bc8c-00a0c91405dd}"),
            new Win32kRawDevice(0x00010002, RimTypeKeyboard, @"\\?\HID#VID_046D&PID_C31C&MI_00#7&1a2b3c4d&0&0000#{884b96c3-56ef-11d1-bc8c-00a0c91405dd}"),
        };

        private struct RawInputRegistration
        {
            public ushort UsagePage;
            public ushort Usage;
            public uint Flags;
            public ulong Target;
        }

        private struct RawRecord
        {
            public uint Handle;
            public uint Type;
            public ulong Device;
            public ushort ButtonFlags;
            public int LastX;
            public int LastY;
            public ushort MakeCode;
            public ushort KeyFlags;
            public ushort VKey;
            public uint KeyMessage;
        }

        private sealed class RawInputState
        {
            public readonly List<RawInputRegistration> Registrations = new();
            public readonly RawRecord[] Records = new RawRecord[RecordSlots];
            public uint NextHandle = 1;
            public bool HavePointer;
            public int PointerX;
            public int PointerY;
            public bool WarpPending;
            public int WarpX;
            public int WarpY;
        }

        private static readonly ConditionalWeakTable<BinaryEmulator, RawInputState> States = new();

        private static RawInputState GetState(BinaryEmulator Instance)
        {
            return States.GetValue(Instance, static _ => new RawInputState());
        }

        internal static int DeviceCount => Devices.Length;

        internal static Win32kRawDevice GetDevice(int Index) => Devices[Index];

        internal static bool TryGetDevice(ulong Handle, out Win32kRawDevice Device)
        {
            for (int Index = 0; Index < Devices.Length; Index++)
            {
                if (Devices[Index].Handle == Handle)
                {
                    Device = Devices[Index];
                    return true;
                }
            }

            Device = default;
            return false;
        }

        internal static uint HeaderSize(BinaryEmulator Instance)
        {
            return Instance.WinHelper.PointerSize == 8 ? HeaderSize64 : HeaderSize32;
        }

        internal static void Register(BinaryEmulator Instance, ushort UsagePage, ushort Usage, uint Flags, ulong Target)
        {
            List<RawInputRegistration> Registrations = GetState(Instance).Registrations;

            for (int Index = Registrations.Count - 1; Index >= 0; Index--)
            {
                if (Registrations[Index].UsagePage == UsagePage && Registrations[Index].Usage == Usage)
                    Registrations.RemoveAt(Index);
            }

            if ((Flags & RIDEV_REMOVE) != 0)
                return;

            Registrations.Add(new RawInputRegistration
            {
                UsagePage = UsagePage,
                Usage = Usage,
                Flags = Flags,
                Target = Target,
            });
        }

        internal static int RegistrationCount(BinaryEmulator Instance) => GetState(Instance).Registrations.Count;

        internal static bool TryGetRegistration(BinaryEmulator Instance, int Index, out ushort UsagePage, out ushort Usage, out uint Flags, out ulong Target)
        {
            List<RawInputRegistration> Registrations = GetState(Instance).Registrations;
            UsagePage = 0;
            Usage = 0;
            Flags = 0;
            Target = 0;

            if ((uint)Index >= (uint)Registrations.Count)
                return false;

            RawInputRegistration Registration = Registrations[Index];
            UsagePage = Registration.UsagePage;
            Usage = Registration.Usage;
            Flags = Registration.Flags;
            Target = Registration.Target;
            return true;
        }

        /// <summary>
        /// Resolves the window a usage's raw input goes to, and whether that usage still gets legacy messages.
        /// </summary>
        private static bool TryResolveUsage(RawInputState State, ushort Usage, out ulong Target, out bool NoLegacy)
        {
            Target = 0;
            NoLegacy = false;

            bool Found = false;
            for (int Index = 0; Index < State.Registrations.Count; Index++)
            {
                RawInputRegistration Registration = State.Registrations[Index];
                if (Registration.UsagePage != UsagePageGeneric)
                    continue;

                // RIDEV_NOLEGACY is RIDEV_EXCLUDE | RIDEV_PAGEONLY, so the three selectors share one field.
                uint Selector = Registration.Flags & RIDEV_NOLEGACY;
                bool Matches = Registration.Usage == Usage || (Selector == RIDEV_PAGEONLY && Registration.Usage == 0);
                if (!Matches)
                    continue;

                if (Selector == RIDEV_EXCLUDE)
                    return false;

                Target = Registration.Target;
                NoLegacy = Selector == RIDEV_NOLEGACY;
                Found = true;

                if (Registration.Usage == Usage)
                    break;
            }

            return Found;
        }

        internal static void ResetPointerBaseline(BinaryEmulator Instance, int ClientX, int ClientY)
        {
            RawInputState State = GetState(Instance);
            State.WarpPending = true;
            State.WarpX = ClientX;
            State.WarpY = ClientY;
        }

        /// <summary>
        /// Turns one host input event into raw input for whoever registered for it. Returns whether the legacy
        /// window message still has to be posted.
        /// </summary>
        internal static bool DeliverHostEvent(BinaryEmulator Instance, ulong Foreground, uint Message, ulong WParam, ulong LParam)
        {
            switch (Message)
            {
                case Win32kHelper.WM_MOUSEMOVE:
                case Win32kHelper.WM_LBUTTONDOWN:
                case Win32kHelper.WM_LBUTTONUP:
                case Win32kHelper.WM_RBUTTONDOWN:
                case Win32kHelper.WM_RBUTTONUP:
                    return DeliverMouse(Instance, Foreground, Message, LParam);

                case Win32kHelper.WM_KEYDOWN:
                case Win32kHelper.WM_KEYUP:
                case Win32kHelper.WM_SYSKEYDOWN:
                case Win32kHelper.WM_SYSKEYUP:
                    return DeliverKeyboard(Instance, Foreground, Message, WParam, LParam);

                default:
                    return true;
            }
        }

        /// <summary>
        /// Reports travel the host read off the mouse itself.
        /// </summary>
        internal static void DeliverHostRawMouse(BinaryEmulator Instance, ulong Foreground, int DeltaX, int DeltaY)
        {
            RawInputState State = GetState(Instance);
            if ((DeltaX == 0 && DeltaY == 0) || !TryResolveUsage(State, UsageMouse, out ulong Target, out _))
                return;

            RawRecord Record = default;
            Record.Type = RimTypeMouse;
            Record.Device = Devices[0].Handle;
            Record.LastX = DeltaX;
            Record.LastY = DeltaY;
            Post(Instance, State, Target != 0 ? Target : Foreground, ref Record);
        }

        private static bool DeliverMouse(BinaryEmulator Instance, ulong Foreground, uint Message, ulong LParam)
        {
            RawInputState State = GetState(Instance);
            bool HostReportsTravel = HostEventQueue.RawMouseAvailable;

            int X = (short)(LParam & 0xFFFF);
            int Y = (short)((LParam >> 16) & 0xFFFF);

            // The move a warp causes is not travel the guest asked about, and it only cancels out if it is matched
            // against the position the host really last reported.
            bool WarpEcho = State.WarpPending && X == State.WarpX && Y == State.WarpY;
            if (WarpEcho)
                State.WarpPending = false;

            int DeltaX = State.HavePointer && !WarpEcho && !HostReportsTravel ? X - State.PointerX : 0;
            int DeltaY = State.HavePointer && !WarpEcho && !HostReportsTravel ? Y - State.PointerY : 0;

            State.HavePointer = true;
            State.PointerX = X;
            State.PointerY = Y;

            if (!TryResolveUsage(State, UsageMouse, out ulong Target, out bool NoLegacy))
                return true;

            ushort ButtonFlags = Message switch
            {
                Win32kHelper.WM_LBUTTONDOWN => RI_MOUSE_LEFT_BUTTON_DOWN,
                Win32kHelper.WM_LBUTTONUP => RI_MOUSE_LEFT_BUTTON_UP,
                Win32kHelper.WM_RBUTTONDOWN => RI_MOUSE_RIGHT_BUTTON_DOWN,
                Win32kHelper.WM_RBUTTONUP => RI_MOUSE_RIGHT_BUTTON_UP,
                _ => (ushort)0,
            };

            if (ButtonFlags != 0 || DeltaX != 0 || DeltaY != 0)
            {
                RawRecord Record = default;
                Record.Type = RimTypeMouse;
                Record.Device = Devices[0].Handle;
                Record.ButtonFlags = ButtonFlags;
                Record.LastX = DeltaX;
                Record.LastY = DeltaY;
                Post(Instance, State, Target != 0 ? Target : Foreground, ref Record);
            }

            ConfineHostPointer(Instance, State, Foreground);
            return !NoLegacy;
        }

        private static bool DeliverKeyboard(BinaryEmulator Instance, ulong Foreground, uint Message, ulong WParam, ulong LParam)
        {
            RawInputState State = GetState(Instance);
            if (!TryResolveUsage(State, UsageKeyboard, out ulong Target, out bool NoLegacy))
                return true;

            bool Break = Message == Win32kHelper.WM_KEYUP || Message == Win32kHelper.WM_SYSKEYUP;

            RawRecord Record = default;
            Record.Type = RimTypeKeyboard;
            Record.Device = Devices[1].Handle;
            Record.MakeCode = (ushort)((LParam >> 16) & 0xFF);
            Record.KeyFlags = (ushort)((Break ? RI_KEY_BREAK : 0) | ((LParam & (1UL << 24)) != 0 ? RI_KEY_E0 : 0));
            Record.VKey = (ushort)WParam;
            Record.KeyMessage = Message;
            Post(Instance, State, Target != 0 ? Target : Foreground, ref Record);

            return !NoLegacy;
        }

        private static void Post(BinaryEmulator Instance, RawInputState State, ulong Hwnd, ref RawRecord Record)
        {
            Record.Handle = State.NextHandle;
            State.NextHandle = State.NextHandle == uint.MaxValue ? 1 : State.NextHandle + 1;
            State.Records[Record.Handle % RecordSlots] = Record;

            Win32kHelper.PostMessage(Instance, Hwnd, Win32kHelper.WM_INPUT, 0, Record.Handle);
        }

        // A guest in relative mode hides the pointer and never moves it back, so the pointer walks out of the
        // window and its clicks land somewhere else. It goes back to the middle of the client area before it can
        // reach an edge.
        private static void ConfineHostPointer(BinaryEmulator Instance, RawInputState State, ulong Hwnd)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || Window.Width < MinConfineExtent || Window.Height < MinConfineExtent)
                return;

            int Width = (int)Window.Width;
            int Height = (int)Window.Height;
            int MarginX = Width / 4;
            int MarginY = Height / 4;

            if (State.PointerX >= MarginX && State.PointerX <= Width - MarginX &&
                State.PointerY >= MarginY && State.PointerY <= Height - MarginY)
                return;

            State.WarpPending = true;
            State.WarpX = Width / 2;
            State.WarpY = Height / 2;
            Instance.WinHelper.WarpHostCursor(State.WarpX, State.WarpY);
        }

        private static bool TryGetRecord(BinaryEmulator Instance, ulong Handle, out RawRecord Record)
        {
            RawInputState State = GetState(Instance);
            uint Key = (uint)Handle;
            Record = State.Records[Key % RecordSlots];
            return Key != 0 && Record.Handle == Key;
        }

        private static uint PayloadSize(uint Type) => Type == RimTypeKeyboard ? KeyboardPayloadSize : MousePayloadSize;

        /// <summary>
        /// Answers NtUserGetRawInputData, writing the required size back through SizePtr.
        /// </summary>
        internal static uint ReadData(BinaryEmulator Instance, ulong Handle, uint Command, ulong DataPtr, ulong SizePtr, uint HeaderSizeArg)
        {
            uint Header = HeaderSize(Instance);
            if (HeaderSizeArg != Header || SizePtr == 0 || !Instance.IsRegionMapped(SizePtr, 4))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                return uint.MaxValue;
            }

            if (Command != RID_INPUT && Command != RID_HEADER)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                return uint.MaxValue;
            }

            if (!TryGetRecord(Instance, Handle, out RawRecord Record))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                return uint.MaxValue;
            }

            uint TotalSize = Header + PayloadSize(Record.Type);
            uint Required = Command == RID_HEADER ? Header : TotalSize;

            if (DataPtr == 0)
            {
                Instance._emulator.WriteMemory(SizePtr, Required, 4);
                Instance.SetLastWinError(0);
                return 0;
            }

            uint Capacity = Instance.ReadMemoryUInt(SizePtr);
            if (Capacity < Required)
            {
                Instance._emulator.WriteMemory(SizePtr, Required, 4);
                Instance.SetLastWinError(Win32kHelper.ERROR_INSUFFICIENT_BUFFER);
                return uint.MaxValue;
            }

            if (!Instance.IsRegionMapped(DataPtr, Required))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                return uint.MaxValue;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Required);
            Buffer.Clear();
            WriteHeader(Instance, Buffer, Record, TotalSize);

            if (Command == RID_INPUT)
                WritePayload(Buffer.Slice((int)Header), Record);

            if (!Instance.WriteMemory(DataPtr, Buffer))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                return uint.MaxValue;
            }

            Instance.SetLastWinError(0);
            return Required;
        }

        private static void WriteHeader(BinaryEmulator Instance, Span<byte> Buffer, in RawRecord Record, uint TotalSize)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0, 4), Record.Type);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(4, 4), TotalSize);

            if (Instance.WinHelper.PointerSize == 8)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(8, 8), Record.Device);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(16, 8), 0);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(8, 4), (uint)Record.Device);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(12, 4), 0);
            }
        }

        private static void WritePayload(Span<byte> Buffer, in RawRecord Record)
        {
            if (Record.Type == RimTypeKeyboard)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0, 2), Record.MakeCode);
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(2, 2), Record.KeyFlags);
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(6, 2), Record.VKey);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(8, 4), Record.KeyMessage);
                return;
            }

            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0, 2), MOUSE_MOVE_RELATIVE);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(4, 2), Record.ButtonFlags);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(12, 4), Record.LastX);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(16, 4), Record.LastY);
        }

        /// <summary>
        /// Fills a RID_DEVICE_INFO for one of the emulated devices.
        /// </summary>
        internal static void WriteDeviceInfo(Span<byte> Buffer, in Win32kRawDevice Device)
        {
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0, 4), DeviceInfoSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(4, 4), Device.Type);

            if (Device.Type == RimTypeKeyboard)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(8, 4), 4);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(16, 4), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(20, 4), 12);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(24, 4), 3);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(28, 4), 101);
                return;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(12, 4), 5);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(20, 4), 1);
        }
    }
}
