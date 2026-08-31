using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetClassInfoEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong InstanceHandle = Instance.WinHelper.GetArg(0);
            ulong ClassNamePtr = Instance.WinHelper.GetArg(1);
            ulong WndClassPtr = Instance.WinHelper.GetArg(2);
            ulong MenuNamePtr = Instance.WinHelper.GetArg(3);

            if (ClassNamePtr == 0 || WndClassPtr == 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindowClass WindowClass = ResolveClass(Instance, InstanceHandle, ClassNamePtr);
            if (WindowClass == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_CANNOT_FIND_WND_CLASS);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryWriteWindowClass(Instance, WndClassPtr, WindowClass))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // user32 copies this straight into WNDCLASSEXW.lpszMenuName.
            if (MenuNamePtr != 0)
            {
                if (!Instance.IsRegionMapped(MenuNamePtr, (uint)Instance.WinHelper.PointerSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WinHelper.WritePointer(MenuNamePtr, 0))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(WindowClass.Atom);
            return NTSTATUS.STATUS_SUCCESS;
        }

        /// <summary>
        /// user32 passes an atom class as a UNICODE_STRING whose Buffer holds the atom itself.
        /// </summary>
        private static WinWindowClass ResolveClass(BinaryEmulator Instance, ulong InstanceHandle, ulong ClassNamePtr)
        {
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (!Instance.IsRegionMapped(ClassNamePtr, PointerSize * 2))
                return null;

            ulong Buffer = Instance.WinHelper.ReadPointer(ClassNamePtr + PointerSize);
            if (Buffer != 0 && Buffer <= 0xFFFF)
                return Instance.WinHelper.GetWindowClass((ushort)Buffer);

            string Name = Win32kHelper.ReadUnicodeString(Instance, ClassNamePtr);
            if (string.IsNullOrEmpty(Name))
                return null;

            return Instance.WinHelper.GetWindowClass(InstanceHandle, Name, string.Empty);
        }
    }
}
