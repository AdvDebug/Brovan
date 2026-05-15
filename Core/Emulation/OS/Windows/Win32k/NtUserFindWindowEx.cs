using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserFindWindowEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ParentHwnd = Instance.WinHelper.GetArg64(0);
            ulong ChildAfterHwnd = Instance.WinHelper.GetArg64(1);
            ulong ClassNamePtr = Instance.WinHelper.GetArg64(2);
            ulong WindowNamePtr = Instance.WinHelper.GetArg64(3);
            ulong Unknown = Instance.WinHelper.GetArg64(4, true);

            if (!TryReadOptionalUnicodeString64(Instance, ClassNamePtr, out string ClassName, out bool HasClassName))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!TryReadOptionalUnicodeString64(Instance, WindowNamePtr, out string WindowName, out bool HasWindowName))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            List<ulong> SearchList = new List<ulong>();

            if (ParentHwnd == 0)
            {
                SearchList.AddRange(Instance.WinHelper.TopLevelWindows);
            }
            else
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(ParentHwnd);
                if (Parent == null)
                {
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                SearchList.AddRange(Parent.Children);
            }

            bool StartChecking = ChildAfterHwnd == 0;

            foreach (ulong Hwnd in SearchList)
            {
                if (!StartChecking)
                {
                    if (Hwnd == ChildAfterHwnd)
                        StartChecking = true;

                    continue;
                }

                if (Hwnd == ChildAfterHwnd)
                    continue;

                WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
                if (Window == null)
                    continue;

                if (HasClassName && !string.Equals(Window.ClassName ?? string.Empty, ClassName ?? string.Empty, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (HasWindowName && !string.Equals(Window.Title ?? string.Empty, WindowName ?? string.Empty, StringComparison.OrdinalIgnoreCase))
                    continue;

                Instance.SetRawSyscallReturn(Window.Hwnd);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryReadOptionalUnicodeString64(BinaryEmulator Instance, ulong Address, out string Value, out bool Present)
        {
            Value = null;
            Present = false;

            if (Address == 0)
                return true;

            if (!StructSerializer.ParseStruct(Instance, Address, out UNICODE_STRING64 UnicodeString))
                return false;

            Present = true;

            if (UnicodeString.Buffer == 0 || UnicodeString.Length == 0)
            {
                Value = string.Empty;
                return true;
            }

            Value = Instance._emulator.ReadMemoryString(UnicodeString.Buffer, UnicodeString.Length, Encoding.Unicode)?.TrimEnd('\0');
            return true;
        }
    }
}