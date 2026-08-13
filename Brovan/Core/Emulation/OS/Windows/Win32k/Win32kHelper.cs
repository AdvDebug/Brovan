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

    internal readonly struct Win32kKeyMapping
    {
        public readonly byte ScanCode;
        public readonly bool Extended;
        public readonly byte VirtualKey;
        public readonly byte SidedVirtualKey;
        public readonly char Character;
        public readonly char ShiftedCharacter;

        public Win32kKeyMapping(byte ScanCode, bool Extended, byte VirtualKey, byte SidedVirtualKey, char Character, char ShiftedCharacter)
        {
            this.ScanCode = ScanCode;
            this.Extended = Extended;
            this.VirtualKey = VirtualKey;
            this.SidedVirtualKey = SidedVirtualKey;
            this.Character = Character;
            this.ShiftedCharacter = ShiftedCharacter;
        }
    }

    internal struct Win32kBitmap
    {
        public int Width;
        public int Height;
        public ushort Planes;
        public ushort BitsPerPixel;
        public int Stride;
        public ulong BitsAddress;
        public uint BitsSize;
        public bool DibSection;
        public bool TopDown;
    }

    internal static class Win32kHelper
    {
        internal const uint ERROR_INVALID_PARAMETER = 87;
        internal const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
        internal const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

        internal const byte PenHandleType = 0x30;
        internal const byte BrushHandleType = 0x10;
        internal const byte BitmapHandleType = 0x05;

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
        internal const uint WM_DPICHANGED = 0x02E0;
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
        private const long MaxBitmapBytes = 0x40000000;
        private const uint BitmapCopyChunkBytes = 0x10000;

        private static readonly ConditionalWeakTable<BinaryEmulator, Win32kState> States = new();

        private sealed class Win32kState
        {
            public readonly Queue<Win32kMessage> MessageQueue = new();
            public readonly Dictionary<ulong, Win32kDeviceContext> DeviceContexts = new();
            public readonly Dictionary<ulong, Win32kPenBrush> PenBrushObjects = new();
            public readonly Dictionary<ulong, Win32kBitmap> Bitmaps = new();
            public ulong NextDeviceContext = FirstDeviceContextHandle;
            public ulong CaptureWindow;
            public bool QuitPosted;
            public ulong QuitExitCode;
            public int CursorX;
            public int CursorY;
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
            if (GdiHandle == 0)
                return 0;

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
            if (!State.DeviceContexts.Remove(Hdc))
                return false;

            Instance.WinHelper.FreeGdiHandle(Hdc);
            return true;
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

        internal static bool TryGetPenBrush(BinaryEmulator Instance, ulong Handle, out Win32kPenBrush PenBrush)
        {
            if (Handle != 0)
                return GetState(Instance).PenBrushObjects.TryGetValue(Handle, out PenBrush);

            PenBrush = default;
            return false;
        }

        internal static bool RemovePenBrush(BinaryEmulator Instance, ulong Handle)
        {
            return GetState(Instance).PenBrushObjects.Remove(Handle);
        }

        internal const uint MapVirtualKeyToScanCode = 0;
        internal const uint MapVirtualScanCodeToKey = 1;
        internal const uint MapVirtualKeyToChar = 2;
        internal const uint MapVirtualScanCodeToKeyEx = 3;
        internal const uint MapVirtualKeyToScanCodeEx = 4;

        internal const byte VkBack = 0x08;
        internal const byte VkTab = 0x09;
        internal const byte VkReturn = 0x0D;
        internal const byte VkShift = 0x10;
        internal const byte VkControl = 0x11;
        internal const byte VkMenu = 0x12;
        internal const byte VkPause = 0x13;
        internal const byte VkCapital = 0x14;
        internal const byte VkEscape = 0x1B;
        internal const byte VkSpace = 0x20;
        internal const byte VkPrior = 0x21;
        internal const byte VkNext = 0x22;
        internal const byte VkEnd = 0x23;
        internal const byte VkHome = 0x24;
        internal const byte VkLeft = 0x25;
        internal const byte VkUp = 0x26;
        internal const byte VkRight = 0x27;
        internal const byte VkDown = 0x28;
        internal const byte VkSnapshot = 0x2C;
        internal const byte VkInsert = 0x2D;
        internal const byte VkDelete = 0x2E;
        internal const byte VkLWin = 0x5B;
        internal const byte VkRWin = 0x5C;
        internal const byte VkApps = 0x5D;
        internal const byte VkNumpad0 = 0x60;
        internal const byte VkMultiply = 0x6A;
        internal const byte VkAdd = 0x6B;
        internal const byte VkSubtract = 0x6D;
        internal const byte VkDecimal = 0x6E;
        internal const byte VkDivide = 0x6F;
        internal const byte VkF1 = 0x70;
        internal const byte VkNumLock = 0x90;
        internal const byte VkScroll = 0x91;
        internal const byte VkLShift = 0xA0;
        internal const byte VkRShift = 0xA1;
        internal const byte VkLControl = 0xA2;
        internal const byte VkRControl = 0xA3;
        internal const byte VkLMenu = 0xA4;
        internal const byte VkRMenu = 0xA5;
        internal const byte VkOem1 = 0xBA;
        internal const byte VkOemPlus = 0xBB;
        internal const byte VkOemComma = 0xBC;
        internal const byte VkOemMinus = 0xBD;
        internal const byte VkOemPeriod = 0xBE;
        internal const byte VkOem2 = 0xBF;
        internal const byte VkOem3 = 0xC0;
        internal const byte VkOem4 = 0xDB;
        internal const byte VkOem5 = 0xDC;
        internal const byte VkOem6 = 0xDD;
        internal const byte VkOem7 = 0xDE;
        internal const byte VkOem102 = 0xE2;

        internal const uint ExtendedScanCodePrefix = 0xE000;

        /// <summary>
        /// US layout, set 1 scan codes. Non-extended rows come first so a virtual-key lookup resolves to the
        /// main-keyboard scan code the way MapVirtualKey does (VK_RETURN to 0x1C, not to the numpad's 0xE01C).
        /// </summary>
        private static readonly Win32kKeyMapping[] KeyMappings =
        {
            new(0x01, false, VkEscape, VkEscape, '\x1B', '\x1B'),
            new(0x02, false, (byte)'1', (byte)'1', '1', '!'),
            new(0x03, false, (byte)'2', (byte)'2', '2', '@'),
            new(0x04, false, (byte)'3', (byte)'3', '3', '#'),
            new(0x05, false, (byte)'4', (byte)'4', '4', '$'),
            new(0x06, false, (byte)'5', (byte)'5', '5', '%'),
            new(0x07, false, (byte)'6', (byte)'6', '6', '^'),
            new(0x08, false, (byte)'7', (byte)'7', '7', '&'),
            new(0x09, false, (byte)'8', (byte)'8', '8', '*'),
            new(0x0A, false, (byte)'9', (byte)'9', '9', '('),
            new(0x0B, false, (byte)'0', (byte)'0', '0', ')'),
            new(0x0C, false, VkOemMinus, VkOemMinus, '-', '_'),
            new(0x0D, false, VkOemPlus, VkOemPlus, '=', '+'),
            new(0x0E, false, VkBack, VkBack, '\b', '\b'),
            new(0x0F, false, VkTab, VkTab, '\t', '\t'),
            new(0x10, false, (byte)'Q', (byte)'Q', 'q', 'Q'),
            new(0x11, false, (byte)'W', (byte)'W', 'w', 'W'),
            new(0x12, false, (byte)'E', (byte)'E', 'e', 'E'),
            new(0x13, false, (byte)'R', (byte)'R', 'r', 'R'),
            new(0x14, false, (byte)'T', (byte)'T', 't', 'T'),
            new(0x15, false, (byte)'Y', (byte)'Y', 'y', 'Y'),
            new(0x16, false, (byte)'U', (byte)'U', 'u', 'U'),
            new(0x17, false, (byte)'I', (byte)'I', 'i', 'I'),
            new(0x18, false, (byte)'O', (byte)'O', 'o', 'O'),
            new(0x19, false, (byte)'P', (byte)'P', 'p', 'P'),
            new(0x1A, false, VkOem4, VkOem4, '[', '{'),
            new(0x1B, false, VkOem6, VkOem6, ']', '}'),
            new(0x1C, false, VkReturn, VkReturn, '\r', '\r'),
            new(0x1D, false, VkControl, VkLControl, '\0', '\0'),
            new(0x1E, false, (byte)'A', (byte)'A', 'a', 'A'),
            new(0x1F, false, (byte)'S', (byte)'S', 's', 'S'),
            new(0x20, false, (byte)'D', (byte)'D', 'd', 'D'),
            new(0x21, false, (byte)'F', (byte)'F', 'f', 'F'),
            new(0x22, false, (byte)'G', (byte)'G', 'g', 'G'),
            new(0x23, false, (byte)'H', (byte)'H', 'h', 'H'),
            new(0x24, false, (byte)'J', (byte)'J', 'j', 'J'),
            new(0x25, false, (byte)'K', (byte)'K', 'k', 'K'),
            new(0x26, false, (byte)'L', (byte)'L', 'l', 'L'),
            new(0x27, false, VkOem1, VkOem1, ';', ':'),
            new(0x28, false, VkOem7, VkOem7, '\'', '"'),
            new(0x29, false, VkOem3, VkOem3, '`', '~'),
            new(0x2A, false, VkShift, VkLShift, '\0', '\0'),
            new(0x2B, false, VkOem5, VkOem5, '\\', '|'),
            new(0x2C, false, (byte)'Z', (byte)'Z', 'z', 'Z'),
            new(0x2D, false, (byte)'X', (byte)'X', 'x', 'X'),
            new(0x2E, false, (byte)'C', (byte)'C', 'c', 'C'),
            new(0x2F, false, (byte)'V', (byte)'V', 'v', 'V'),
            new(0x30, false, (byte)'B', (byte)'B', 'b', 'B'),
            new(0x31, false, (byte)'N', (byte)'N', 'n', 'N'),
            new(0x32, false, (byte)'M', (byte)'M', 'm', 'M'),
            new(0x33, false, VkOemComma, VkOemComma, ',', '<'),
            new(0x34, false, VkOemPeriod, VkOemPeriod, '.', '>'),
            new(0x35, false, VkOem2, VkOem2, '/', '?'),
            new(0x36, false, VkShift, VkRShift, '\0', '\0'),
            new(0x37, false, VkMultiply, VkMultiply, '*', '*'),
            new(0x38, false, VkMenu, VkLMenu, '\0', '\0'),
            new(0x39, false, VkSpace, VkSpace, ' ', ' '),
            new(0x3A, false, VkCapital, VkCapital, '\0', '\0'),
            new(0x3B, false, VkF1 + 0, VkF1 + 0, '\0', '\0'),
            new(0x3C, false, VkF1 + 1, VkF1 + 1, '\0', '\0'),
            new(0x3D, false, VkF1 + 2, VkF1 + 2, '\0', '\0'),
            new(0x3E, false, VkF1 + 3, VkF1 + 3, '\0', '\0'),
            new(0x3F, false, VkF1 + 4, VkF1 + 4, '\0', '\0'),
            new(0x40, false, VkF1 + 5, VkF1 + 5, '\0', '\0'),
            new(0x41, false, VkF1 + 6, VkF1 + 6, '\0', '\0'),
            new(0x42, false, VkF1 + 7, VkF1 + 7, '\0', '\0'),
            new(0x43, false, VkF1 + 8, VkF1 + 8, '\0', '\0'),
            new(0x44, false, VkF1 + 9, VkF1 + 9, '\0', '\0'),
            new(0x45, false, VkNumLock, VkNumLock, '\0', '\0'),
            new(0x46, false, VkScroll, VkScroll, '\0', '\0'),
            new(0x47, false, VkNumpad0 + 7, VkNumpad0 + 7, '7', '7'),
            new(0x48, false, VkNumpad0 + 8, VkNumpad0 + 8, '8', '8'),
            new(0x49, false, VkNumpad0 + 9, VkNumpad0 + 9, '9', '9'),
            new(0x4A, false, VkSubtract, VkSubtract, '-', '-'),
            new(0x4B, false, VkNumpad0 + 4, VkNumpad0 + 4, '4', '4'),
            new(0x4C, false, VkNumpad0 + 5, VkNumpad0 + 5, '5', '5'),
            new(0x4D, false, VkNumpad0 + 6, VkNumpad0 + 6, '6', '6'),
            new(0x4E, false, VkAdd, VkAdd, '+', '+'),
            new(0x4F, false, VkNumpad0 + 1, VkNumpad0 + 1, '1', '1'),
            new(0x50, false, VkNumpad0 + 2, VkNumpad0 + 2, '2', '2'),
            new(0x51, false, VkNumpad0 + 3, VkNumpad0 + 3, '3', '3'),
            new(0x52, false, VkNumpad0 + 0, VkNumpad0 + 0, '0', '0'),
            new(0x53, false, VkDecimal, VkDecimal, '.', '.'),
            new(0x56, false, VkOem102, VkOem102, '\\', '|'),
            new(0x57, false, VkF1 + 10, VkF1 + 10, '\0', '\0'),
            new(0x58, false, VkF1 + 11, VkF1 + 11, '\0', '\0'),
            new(0x45, false, VkPause, VkPause, '\0', '\0'),
            new(0x1C, true, VkReturn, VkReturn, '\r', '\r'),
            new(0x1D, true, VkControl, VkRControl, '\0', '\0'),
            new(0x35, true, VkDivide, VkDivide, '/', '/'),
            new(0x37, true, VkSnapshot, VkSnapshot, '\0', '\0'),
            new(0x38, true, VkMenu, VkRMenu, '\0', '\0'),
            new(0x47, true, VkHome, VkHome, '\0', '\0'),
            new(0x48, true, VkUp, VkUp, '\0', '\0'),
            new(0x49, true, VkPrior, VkPrior, '\0', '\0'),
            new(0x4B, true, VkLeft, VkLeft, '\0', '\0'),
            new(0x4D, true, VkRight, VkRight, '\0', '\0'),
            new(0x4F, true, VkEnd, VkEnd, '\0', '\0'),
            new(0x50, true, VkDown, VkDown, '\0', '\0'),
            new(0x51, true, VkNext, VkNext, '\0', '\0'),
            new(0x52, true, VkInsert, VkInsert, '\0', '\0'),
            new(0x53, true, VkDelete, VkDelete, '\0', '\0'),
            new(0x5B, true, VkLWin, VkLWin, '\0', '\0'),
            new(0x5C, true, VkRWin, VkRWin, '\0', '\0'),
            new(0x5D, true, VkApps, VkApps, '\0', '\0'),
        };

        internal static uint MapVirtualKey(uint Code, uint MapType)
        {
            switch (MapType)
            {
                case MapVirtualKeyToScanCode:
                case MapVirtualKeyToScanCodeEx:
                {
                    for (int i = 0; i < KeyMappings.Length; i++)
                    {
                        Win32kKeyMapping Mapping = KeyMappings[i];
                        if (Mapping.VirtualKey != Code && Mapping.SidedVirtualKey != Code)
                            continue;

                        if (MapType == MapVirtualKeyToScanCodeEx && Mapping.Extended)
                            return ExtendedScanCodePrefix | Mapping.ScanCode;

                        return Mapping.ScanCode;
                    }

                    return 0;
                }

                case MapVirtualScanCodeToKey:
                case MapVirtualScanCodeToKeyEx:
                {
                    bool Extended = (Code & 0xFF00) == ExtendedScanCodePrefix;
                    byte ScanCode = (byte)Code;

                    for (int i = 0; i < KeyMappings.Length; i++)
                    {
                        Win32kKeyMapping Mapping = KeyMappings[i];
                        if (Mapping.ScanCode != ScanCode || Mapping.Extended != Extended)
                            continue;

                        return MapType == MapVirtualScanCodeToKeyEx ? Mapping.SidedVirtualKey : Mapping.VirtualKey;
                    }

                    return 0;
                }

                case MapVirtualKeyToChar:
                {
                    if (!TryGetKeyMapping(Code, out Win32kKeyMapping Mapping) || Mapping.Character == '\0')
                        return 0;

                    return char.ToUpperInvariant(Mapping.Character);
                }
            }

            return 0;
        }

        internal static bool TryTranslateKey(uint VirtualKey, bool Shift, bool CapsLock, bool Control, out char Character)
        {
            Character = '\0';
            if (!TryGetKeyMapping(VirtualKey, out Win32kKeyMapping Mapping))
                return false;

            char Translated = Shift ? Mapping.ShiftedCharacter : Mapping.Character;
            if (Translated == '\0')
                return false;

            if (CapsLock && char.IsAsciiLetter(Mapping.Character))
                Translated = Shift ? Mapping.Character : Mapping.ShiftedCharacter;

            if (Control)
            {
                if (!char.IsAsciiLetter(Translated))
                    return false;

                Translated = (char)(char.ToUpperInvariant(Translated) - 'A' + 1);
            }

            Character = Translated;
            return true;
        }

        private static bool TryGetKeyMapping(uint VirtualKey, out Win32kKeyMapping Mapping)
        {
            for (int i = 0; i < KeyMappings.Length; i++)
            {
                if (KeyMappings[i].VirtualKey == VirtualKey || KeyMappings[i].SidedVirtualKey == VirtualKey)
                {
                    Mapping = KeyMappings[i];
                    return true;
                }
            }

            Mapping = default;
            return false;
        }

        /// <summary>
        /// Byte length of one scanline. GDI pads plain bitmaps to a WORD and DIB sections to a DWORD.
        /// </summary>
        internal static int GetBitmapStride(int Width, int Planes, int BitsPerPixel, bool DibSection)
        {
            long Bits = (long)Width * Planes * BitsPerPixel;
            if (Bits <= 0 || Bits > int.MaxValue)
                return 0;

            return DibSection ? (int)(((Bits + 31) / 32) * 4) : (int)(((Bits + 15) / 16) * 2);
        }

        internal static ulong CreateBitmap(BinaryEmulator Instance, int Width, int Height, ushort Planes, ushort BitsPerPixel, bool DibSection, bool TopDown)
        {
            int Stride = GetBitmapStride(Width, Planes, BitsPerPixel, DibSection);
            if (Width <= 0 || Height <= 0 || Planes == 0 || BitsPerPixel == 0 || Stride == 0)
                return 0;

            long TotalBytes = (long)Stride * Height;
            if (TotalBytes > MaxBitmapBytes)
                return 0;

            ulong Handle = Instance.WinHelper.AllocateGdiHandle(BitmapHandleType);
            if (Handle == 0)
                return 0;

            ulong BitsAddress = Instance.MapUniqueAddress((ulong)TotalBytes, MemoryProtection.ReadWrite);
            if (BitsAddress == 0)
            {
                Instance.WinHelper.FreeGdiHandle(Handle);
                return 0;
            }

            GetState(Instance).Bitmaps[Handle] = new Win32kBitmap
            {
                Width = Width,
                Height = Height,
                Planes = Planes,
                BitsPerPixel = BitsPerPixel,
                Stride = Stride,
                BitsAddress = BitsAddress,
                BitsSize = (uint)TotalBytes,
                DibSection = DibSection,
                TopDown = TopDown,
            };
            return Handle;
        }

        internal static bool CopyBitmapBitsIn(BinaryEmulator Instance, in Win32kBitmap Bitmap, ulong SourceAddress)
        {
            if (SourceAddress == 0 || !Instance.IsRegionMapped(SourceAddress, Bitmap.BitsSize))
                return false;

            Span<byte> Chunk = Instance.WinHelper.Shared.GetSpan(BitmapCopyChunkBytes);
            for (uint Copied = 0; Copied < Bitmap.BitsSize;)
            {
                int Size = (int)Math.Min(BitmapCopyChunkBytes, Bitmap.BitsSize - Copied);
                Span<byte> Slice = Chunk.Slice(0, Size);
                if (!Instance.ReadMemory(SourceAddress + Copied, Slice, (uint)Size))
                    return false;

                if (!Instance.WriteMemory(Bitmap.BitsAddress + Copied, Slice))
                    return false;

                Copied += (uint)Size;
            }

            return true;
        }

        internal static bool TryGetBitmap(BinaryEmulator Instance, ulong Handle, out Win32kBitmap Bitmap)
        {
            if (Handle != 0)
                return GetState(Instance).Bitmaps.TryGetValue(Handle, out Bitmap);

            Bitmap = default;
            return false;
        }

        internal static bool RemoveBitmap(BinaryEmulator Instance, ulong Handle)
        {
            Win32kState State = GetState(Instance);
            if (!State.Bitmaps.Remove(Handle, out Win32kBitmap Bitmap))
                return false;

            Instance.UnmapMemoryRegion(Bitmap.BitsAddress);
            return true;
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

            // Nothing can be delivered before the guest makes a window visible, and the host queue must survive
            // until then: consuming the repaint flag (or draining input) here would discard the only events a
            // thread parked in MsgWaitForMultipleObjectsEx can ever be woken by.
            if (Foreground == 0)
                return;

            Win32kDpi.DrainHostDpiChange(Instance);

            if (HostEventQueue.ConsumeRepaint())
                InvalidateWindow(Instance, Foreground);

            Win32kState State = GetState(Instance);
            for (int i = 0; i < MaxHostInputEventsPerDrain; i++)
            {
                if (!HostEventQueue.TryDequeue(out uint Message, out ulong WParam, out ulong LParam))
                    break;

                if (Message >= WM_MOUSEMOVE && Message <= WM_RBUTTONUP)
                {
                    State.CursorX = (short)(LParam & 0xFFFF);
                    State.CursorY = (short)((LParam >> 16) & 0xFFFF);
                }

                PostMessage(Instance, Foreground, Message, WParam, LParam);
            }
        }

        /// <summary>
        /// Screen position of the pointer, tracked from the client-relative coordinates the host window manager
        /// reports for the foreground window.
        /// </summary>
        internal static void GetCursorPosition(BinaryEmulator Instance, out int X, out int Y)
        {
            DrainHostEvents(Instance);

            Win32kState State = GetState(Instance);
            X = State.CursorX;
            Y = State.CursorY;

            WinWindow Foreground = Instance.WinHelper.GetWindow(Instance.WinHelper.GetForegroundWindow());
            if (Foreground == null)
                return;

            X += Foreground.X;
            Y += Foreground.Y;
        }

        internal static void SetCursorPosition(BinaryEmulator Instance, int X, int Y)
        {
            DrainHostEvents(Instance);

            WinWindow Foreground = Instance.WinHelper.GetWindow(Instance.WinHelper.GetForegroundWindow());
            int ClientX = Foreground == null ? X : X - Foreground.X;
            int ClientY = Foreground == null ? Y : Y - Foreground.Y;

            Win32kState State = GetState(Instance);
            State.CursorX = ClientX;
            State.CursorY = ClientY;

            Instance.WinHelper.WarpHostCursor(ClientX, ClientY);
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
