using System.Runtime.InteropServices;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRegisterClassExWOW : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            const uint ERROR_INVALID_PARAMETER = 87;

            ulong WndClassPtr = Instance.WinHelper.GetArg64(0);
            ulong ClassNamePtr = Instance.WinHelper.GetArg64(1);
            ulong ClassVersionPtr = Instance.WinHelper.GetArg64(2);
            ulong ClassMenuNamePtr = Instance.WinHelper.GetArg64(3);
            uint FunctionId = (uint)Instance.WinHelper.GetArg64(4, true);
            uint Flags = (uint)Instance.WinHelper.GetArg64(5, true);
            ulong WowPtr = Instance.WinHelper.GetArg64(6);

            if (WndClassPtr == 0 || ClassNamePtr == 0)
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(WndClassPtr, (ulong)Marshal.SizeOf<WNDCLASSEXW64>()))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!StructSerializer.ParseStruct(Instance, WndClassPtr, out WNDCLASSEXW64 WndClass))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (WndClass.cbSize < Marshal.SizeOf<WNDCLASSEXW64>())
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string ClassName = ReadUnicodeString64(Instance, ClassNamePtr);
            if (string.IsNullOrEmpty(ClassName))
                ClassName = ReadClassNameFromPointer(Instance, WndClass.lpszClassName);

            if (string.IsNullOrEmpty(ClassName))
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string ClassVersion = ReadUnicodeString64(Instance, ClassVersionPtr) ?? string.Empty;
            string MenuName = ReadMenuName(Instance, ClassMenuNamePtr, WndClass.lpszMenuName);

            WinWindowClass RegisteredClass = Instance.WinHelper.RegisterWindowClass(new WinWindowClass
            {
                Name = ClassName,
                Version = ClassVersion,
                MenuName = MenuName,
                InstanceHandle = WndClass.hInstance,
                WndProc = WndClass.lpfnWndProc,
                Style = WndClass.style,
                ClassExtraBytes = WndClass.cbClsExtra,
                WindowExtraBytes = WndClass.cbWndExtra,
                IconHandle = WndClass.hIcon,
                CursorHandle = WndClass.hCursor,
                BackgroundBrush = WndClass.hbrBackground,
                SmallIconHandle = WndClass.hIconSm,
                FunctionId = FunctionId,
                Flags = Flags,
                Ansi = (Flags & 1) != 0,
            });

            if (RegisteredClass == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (WowPtr != 0)
            {
                if (!Instance.IsRegionMapped(WowPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance._emulator.WriteMemory(WowPtr, 0u))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(RegisteredClass.Atom);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ReadUnicodeString64(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0)
                return null;

            if (!StructSerializer.ParseStruct(Instance, Address, out UNICODE_STRING64 String))
                return null;

            if (String.Buffer == 0 || String.Length == 0)
                return string.Empty;

            if (!Instance.IsRegionMapped(String.Buffer, String.Length))
                return null;

            return Instance._emulator.ReadMemoryString(String.Buffer, String.Length, Encoding.Unicode)?.TrimEnd('\0');
        }

        private static string ReadClassNameFromPointer(BinaryEmulator Instance, ulong Pointer)
        {
            if (Pointer == 0)
                return null;

            if (Pointer <= 0xFFFF)
                return $"#ATOM_{Pointer:X}";

            return ReadNullTerminatedUnicodeString(Instance, Pointer);
        }

        private static string ReadMenuName(BinaryEmulator Instance, ulong ClassMenuNamePtr, ulong WndClassMenuNamePtr)
        {
            if (ClassMenuNamePtr != 0 && Instance.IsRegionMapped(ClassMenuNamePtr, (ulong)Marshal.SizeOf<CLSMENUNAME64>()))
            {
                if (StructSerializer.ParseStruct(Instance, ClassMenuNamePtr, out CLSMENUNAME64 MenuName))
                {
                    string Name = ReadUnicodeString64(Instance, MenuName.pusMenuName);
                    if (!string.IsNullOrEmpty(Name))
                        return Name;

                    Name = ReadNullTerminatedUnicodeString(Instance, MenuName.pwszClientUnicodeMenuName);
                    if (!string.IsNullOrEmpty(Name))
                        return Name;
                }
            }

            if (WndClassMenuNamePtr == 0)
                return null;

            if (WndClassMenuNamePtr <= 0xFFFF)
                return $"#ATOM_{WndClassMenuNamePtr:X}";

            return ReadNullTerminatedUnicodeString(Instance, WndClassMenuNamePtr);
        }

        private static string ReadNullTerminatedUnicodeString(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0)
                return null;

            if (!Instance.IsRegionMapped(Address, 2))
                return null;

            StringBuilder Builder = new StringBuilder();
            ulong Current = Address;

            for (int i = 0; i < 32767; i++)
            {
                if (!Instance.IsRegionMapped(Current, 2))
                    return null;

                byte[] Bytes = Instance._emulator.ReadMemory(Current, 2);
                ushort Character = BitConverter.ToUInt16(Bytes, 0);
                if (Character == 0)
                    return Builder.ToString();

                Builder.Append((char)Character);
                Current += 2;
            }

            return Builder.ToString();
        }

        [StructLayout(LayoutKind.Explicit, Size = 80)]
        private struct WNDCLASSEXW64
        {
            [FieldOffset(0)] public uint cbSize;
            [FieldOffset(4)] public uint style;
            [FieldOffset(8)] public ulong lpfnWndProc;
            [FieldOffset(16)] public int cbClsExtra;
            [FieldOffset(20)] public int cbWndExtra;
            [FieldOffset(24)] public ulong hInstance;
            [FieldOffset(32)] public ulong hIcon;
            [FieldOffset(40)] public ulong hCursor;
            [FieldOffset(48)] public ulong hbrBackground;
            [FieldOffset(56)] public ulong lpszMenuName;
            [FieldOffset(64)] public ulong lpszClassName;
            [FieldOffset(72)] public ulong hIconSm;
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        private struct CLSMENUNAME64
        {
            [FieldOffset(0)] public ulong pszClientAnsiMenuName;
            [FieldOffset(8)] public ulong pwszClientUnicodeMenuName;
            [FieldOffset(16)] public ulong pusMenuName;
        }
    }
}
