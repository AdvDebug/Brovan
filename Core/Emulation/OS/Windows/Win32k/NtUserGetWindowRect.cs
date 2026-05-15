using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetWindowRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong RectPtr = Instance.WinHelper.GetArg64(1);
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);

            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (RectPtr == 0 || !Instance.IsRegionMapped(RectPtr, (ulong)Marshal.SizeOf<RECT>()))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            GetAbsolutePosition(Instance, Window, out int Left, out int Top);

            RECT Rect = new RECT
            {
                Left = Left,
                Top = Top,
                Right = Left + (int)Window.Width,
                Bottom = Top + (int)Window.Height
            };

            if (!StructSerializer.WriteStruct(Instance, RectPtr, Rect).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void GetAbsolutePosition(BinaryEmulator Instance, WinWindow Window, out int Left, out int Top)
        {
            Left = Window.X;
            Top = Window.Y;

            ulong ParentHwnd = Window.ParentHwnd;
            while (ParentHwnd != 0)
            {
                WinWindow Parent = Instance.WinHelper.GetWindow(ParentHwnd);
                if (Parent == null)
                    break;

                Left += Parent.X;
                Top += Parent.Y;
                ParentHwnd = Parent.ParentHwnd;
            }
        }
    }
}