using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserCreateWindowEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong exStyleArg = Instance.WinHelper.GetArg(0);
            ulong ClassNamePtr = Instance.WinHelper.GetArg(1);
            ulong ClassVersionPtr = Instance.WinHelper.GetArg(2);
            ulong WindowNamePtr = Instance.WinHelper.GetArg(3);
            ulong StyleArg = Instance.WinHelper.GetArg(4);
            int x = unchecked((int)Instance.WinHelper.GetArg(5));
            int y = unchecked((int)Instance.WinHelper.GetArg(6));
            int width = unchecked((int)Instance.WinHelper.GetArg(7));
            int height = unchecked((int)Instance.WinHelper.GetArg(8));
            ulong ParentHwnd = Instance.WinHelper.GetArg(9);
            ulong MenuHandle = Instance.WinHelper.GetArg(10);
            ulong InstanceHandle = Instance.WinHelper.GetArg(11);
            ulong CreateParam = Instance.WinHelper.GetArg(12);

            if (ParentHwnd != 0 && Instance.WinHelper.GetWindow(ParentHwnd) == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string ClassName = ReadLargeString64(Instance, ClassNamePtr);
            string classVersion = ReadLargeString64(Instance, ClassVersionPtr) ?? string.Empty;
            WinWindowClass WindowClass = null;

            if (ClassNamePtr != 0 && ClassNamePtr <= 0xFFFF)
            {
                WindowClass = Instance.WinHelper.GetWindowClass((ushort)ClassNamePtr);
                ClassName = WindowClass?.Name ?? $"#ATOM_{ClassNamePtr:X}";
            }
            else if (!string.IsNullOrEmpty(ClassName))
            {
                WindowClass = Instance.WinHelper.GetWindowClass(InstanceHandle, ClassName, classVersion);
            }

            string title = ReadLargeString64(Instance, WindowNamePtr) ?? string.Empty;
            ulong hwnd = Instance.WinHelper.AllocateUserHandle();

            WinWindow window = new WinWindow
            {
                Hwnd = hwnd,
                ClassAtom = WindowClass?.Atom ?? 0,
                Title = title,
                ClassName = string.IsNullOrEmpty(ClassName) ? "#UNNAMED" : ClassName,
                Visible = ((uint)StyleArg & 0x10000000U) != 0, // WS_VISIBLE
                Style = (uint)StyleArg,
                ExStyle = (uint)exStyleArg,
                X = x,
                Y = y,
                Width = (uint)Math.Max(width, 0),
                Height = (uint)Math.Max(height, 0),
                ParentHwnd = ParentHwnd,
                MenuHandle = MenuHandle,
                InstanceHandle = InstanceHandle,
                CreateParam = CreateParam,
                OwnerThreadId = Instance.CurrentThread?.ThreadId ?? 0,
                WndProc = WindowClass?.WndProc ?? 0,
                Dirty = true,
            };

            Instance.WinHelper.RegisterWindow(window);
            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(hwnd);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ReadLargeString64(BinaryEmulator Instance, ulong Address)
        {
            if (Address == 0 || Address <= 0xFFFF)
                return null;

            if (!StructSerializer.ParseStruct(Instance, Address, out LARGE_STRING64 value))
                return null;

            uint Length = value.Length & 0x7FFFFFFF;
            if (value.Buffer == 0 || Length == 0)
                return string.Empty;

            Encoding Enc = (value.MaximumLength & 0x80000000u) != 0 ? Encoding.ASCII : Encoding.Unicode;
            return Instance._emulator.ReadMemoryString(value.Buffer, (int)Length, Enc)?.TrimEnd('\0');
        }
    }
}