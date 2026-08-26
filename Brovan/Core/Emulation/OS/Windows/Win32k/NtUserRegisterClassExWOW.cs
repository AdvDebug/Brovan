using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRegisterClassExWOW : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            const uint ERROR_INVALID_PARAMETER = 87;

            ulong WndClassPtr = Instance.WinHelper.GetArg(0);
            ulong ClassNamePtr = Instance.WinHelper.GetArg(1);
            ulong ClassVersionPtr = Instance.WinHelper.GetArg(2);
            ulong ClassMenuNamePtr = Instance.WinHelper.GetArg(3);
            uint FunctionId = (uint)Instance.WinHelper.GetArg(4);
            uint Flags = (uint)Instance.WinHelper.GetArg(5);
            ulong WowPtr = Instance.WinHelper.GetArg(6);

            if (WndClassPtr == 0 || ClassNamePtr == 0)
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryReadWindowClass(Instance, WndClassPtr, out Win32kWindowClassDefinition WndClass))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (WndClass.cbSize < Win32kHelper.WindowClassSize(Instance))
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // Both counts ride into a per-window allocation, so an unusable one is refused here.
            if (WndClass.cbWndExtra < 0 || WndClass.cbWndExtra > Win32kHelper.MaxClassExtraBytes ||
                WndClass.cbClsExtra < 0 || WndClass.cbClsExtra > Win32kHelper.MaxClassExtraBytes)
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string ClassName = Win32kHelper.ReadUnicodeString(Instance, ClassNamePtr);
            if (string.IsNullOrEmpty(ClassName))
                ClassName = ReadClassNameFromPointer(Instance, WndClass.lpszClassName);

            if (string.IsNullOrEmpty(ClassName))
            {
                Instance.SetLastWinError(ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string ClassVersion = Win32kHelper.ReadUnicodeString(Instance, ClassVersionPtr) ?? string.Empty;
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
                FunctionId = Win32kHelper.MaskFunctionId(FunctionId),
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
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (ClassMenuNamePtr != 0 && Instance.IsRegionMapped(ClassMenuNamePtr, PointerSize * 3))
            {
                ulong ClientUnicodeMenuName = Instance.WinHelper.ReadPointer(ClassMenuNamePtr + PointerSize);
                ulong MenuNameString = Instance.WinHelper.ReadPointer(ClassMenuNamePtr + PointerSize * 2);

                string Name = Win32kHelper.ReadUnicodeString(Instance, MenuNameString);
                if (!string.IsNullOrEmpty(Name))
                    return Name;

                Name = ReadNullTerminatedUnicodeString(Instance, ClientUnicodeMenuName);
                if (!string.IsNullOrEmpty(Name))
                    return Name;
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
    }
}
