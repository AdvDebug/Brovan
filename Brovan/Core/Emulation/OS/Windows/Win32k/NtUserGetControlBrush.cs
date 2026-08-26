using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetControlBrush : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Hdc = Instance.WinHelper.GetArg(1);
            uint Message = (uint)Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Parent = Window.ParentHwnd == 0 ? null : Instance.WinHelper.GetWindow(Window.ParentHwnd);

            // The owner picks the colour, and only its own thread may run its window procedure.
            bool OwnedHere = Parent != null && Parent.OwnerThreadId == (Instance.CurrentThread?.ThreadId ?? 0);
            if (OwnedHere && Win32kHelper.InvokeWindowProc(Instance, Parent.Hwnd, Parent.WndProc, Message, Hdc, Hwnd))
                return NTSTATUS.STATUS_SUCCESS;

            Instance.SetLastWinError(0);

            Instance.SetRawSyscallReturn(Instance.WinHelper.GetSystemColorBrush(Win32kHelper.DefaultControlColorIndex(Message)));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
