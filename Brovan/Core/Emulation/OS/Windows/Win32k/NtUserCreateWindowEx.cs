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

            // Without WS_CHILD the argument names the owner, not the parent.
            const uint WS_CHILD = 0x40000000;
            ulong OwnerHwnd = 0;
            if (((uint)StyleArg & WS_CHILD) == 0 && ParentHwnd != Win32kMessageOnlyParent.HwndMessage)
            {
                OwnerHwnd = ParentHwnd;
                ParentHwnd = 0;
            }

            // NT adds these implied styles.
            const uint WS_POPUP = 0x80000000;
            const uint WS_CAPTION = 0x00C00000;
            const uint WS_CLIPSIBLINGS = 0x04000000;
            const uint WS_DLGFRAME = 0x00400000;
            const uint WS_THICKFRAME = 0x00040000;
            const uint WS_EX_DLGMODALFRAME = 0x00000001;
            const uint WS_EX_WINDOWEDGE = 0x00000100;

            uint Style = (uint)StyleArg;
            uint ExStyle = (uint)exStyleArg;
            if ((Style & WS_CHILD) == 0)
            {
                Style |= WS_CLIPSIBLINGS;
                if ((Style & WS_POPUP) == 0)
                    Style |= WS_CAPTION;
            }

            if ((ExStyle & WS_EX_DLGMODALFRAME) != 0 || (Style & (WS_DLGFRAME | WS_THICKFRAME)) != 0)
                ExStyle |= WS_EX_WINDOWEDGE;

            WinWindow window = new WinWindow
            {
                Hwnd = hwnd,
                ClassAtom = WindowClass.Atom,
                Title = title,
                ClassName = string.IsNullOrEmpty(ClassName) ? "#UNNAMED" : ClassName,
                Visible = (Style & 0x10000000U) != 0, // WS_VISIBLE
                Style = Style,
                ExStyle = ExStyle,
                X = x,
                Y = y,
                Width = (uint)Math.Max(width, 0),
                Height = (uint)Math.Max(height, 0),
                ParentHwnd = ParentHwnd,
                OwnerHwnd = OwnerHwnd,
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
            Win32kHelper.ReturnAfterNotifications(Instance, hwnd);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}