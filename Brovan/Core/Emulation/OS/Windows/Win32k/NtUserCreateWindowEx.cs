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
            const int UseDefaultPosition = unchecked((int)0x80000000);

            int x = unchecked((int)Instance.WinHelper.GetArg(5));
            int y = unchecked((int)Instance.WinHelper.GetArg(6));

            if (x == UseDefaultPosition)
                x = 0;

            if (y == UseDefaultPosition)
                y = 0;
            int width = unchecked((int)Instance.WinHelper.GetArg(7));
            int height = unchecked((int)Instance.WinHelper.GetArg(8));
            ulong ParentHwnd = Instance.WinHelper.GetArg(9);
            ulong MenuHandle = Instance.WinHelper.GetArg(10);
            ulong InstanceHandle = Instance.WinHelper.GetArg(11);
            ulong CreateParam = Instance.WinHelper.GetArg(12);

            if (Win32kMessageOnlyParent.IsHwndMessage(ParentHwnd))
            {
                Win32kMessageOnlyParent.Ensure(Instance);
                ParentHwnd = Win32kMessageOnlyParent.HwndMessage;
            }
            else if (ParentHwnd != 0 && Instance.WinHelper.GetWindow(ParentHwnd) == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string ClassName = Win32kHelper.ReadLargeString(Instance, ClassNamePtr);
            string classVersion = Win32kHelper.ReadLargeString(Instance, ClassVersionPtr) ?? string.Empty;
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

            // Answering "no such class" is what makes user32 register a standard control and call back in.
            if (WindowClass == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_CANNOT_FIND_WND_CLASS);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string title = Win32kHelper.ReadLargeString(Instance, WindowNamePtr) ?? string.Empty;
            ulong hwnd = Instance.WinHelper.AllocateUserHandle();

            WinWindow window = new WinWindow
            {
                Hwnd = hwnd,
                ClassAtom = WindowClass.Atom,
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
                WndProc = WindowClass.WndProc,
                WindowExtraBytes = WindowClass.WindowExtraBytes,
                Dirty = true,
            };

            Instance.WinHelper.RegisterWindow(window);
            Instance.SetLastWinError(0);

            WinWindowCreation Creation = new WinWindowCreation { Hwnd = hwnd };
            if (Win32kHelper.SendWindowCreateMessage(Instance, window, Win32kHelper.WM_NCCREATE, Creation))
                return NTSTATUS.STATUS_SUCCESS;

            // The callback path is x64 only, so a 32-bit guest gets the window with none of its creation
            // messages and the class has to cope on its own.
            Instance.SetRawSyscallReturn(hwnd);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}