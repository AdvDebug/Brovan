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
                return Win32kHelper.FailWithError(Instance, ERROR_INVALID_WINDOW_HANDLE);

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
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_CANNOT_FIND_WND_CLASS);

            string title = Win32kHelper.ReadLargeString(Instance, WindowNamePtr) ?? string.Empty;
            ulong hwnd = Instance.WinHelper.AllocateUserHandle();

            // Without WS_CHILD the argument names the owner, not the parent.
            ulong OwnerHwnd = 0;
            if (((uint)StyleArg & Win32kHelper.WindowStyleChild) == 0 && ParentHwnd != Win32kMessageOnlyParent.HwndMessage)
            {
                OwnerHwnd = ParentHwnd;
                ParentHwnd = 0;
            }

            // NT adds these implied styles.
            uint Style = (uint)StyleArg;
            uint ExStyle = (uint)exStyleArg;
            if ((Style & Win32kHelper.WindowStyleChild) == 0)
            {
                Style |= Win32kHelper.WindowStyleClipSiblings;
                if ((Style & Win32kHelper.WindowStylePopup) == 0)
                    Style |= Win32kHelper.WindowStyleCaption;
            }

            if ((ExStyle & Win32kHelper.WindowExStyleDlgModalFrame) != 0
                || (Style & (Win32kHelper.WindowStyleDlgFrame | Win32kHelper.WindowStyleThickFrame)) != 0)
                ExStyle |= Win32kHelper.WindowExStyleWindowEdge;

            WinWindow window = new WinWindow
            {
                Hwnd = hwnd,
                ClassAtom = WindowClass.Atom,
                Title = title,
                ClassName = string.IsNullOrEmpty(ClassName) ? "#UNNAMED" : ClassName,
                Visible = (Style & Win32kHelper.WindowStyleVisible) != 0,
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