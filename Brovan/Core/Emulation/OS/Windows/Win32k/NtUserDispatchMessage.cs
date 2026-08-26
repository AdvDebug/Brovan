using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDispatchMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong MessagePtr = Instance.WinHelper.GetArg(0);
            if (!Win32kHelper.TryReadMessage(Instance, MessagePtr, out Win32kMessage Message))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinWindow Window = Message.Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Message.Hwnd);
            if (Message.Hwnd != 0 && Window == null)
            {
                bool Teardown = Message.Message == Win32kHelper.WM_DESTROY || Message.Message == Win32kHelper.WM_NCDESTROY;
                Window = Teardown ? Instance.WinHelper.GetDestroyedWindow(Message.Hwnd) : null;

                if (Window == null)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (Message.Message == Win32kHelper.WM_NCDESTROY)
                    Instance.WinHelper.ForgetDestroyedWindow(Message.Hwnd);
            }

            if (Window == null || Window.WndProc == 0)
            {
                ulong FallbackResult = Win32kHelper.DispatchMessage(Instance, Message);
                Instance.SetRawSyscallReturn(FallbackResult);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.InvokeWindowProc(Instance, Message.Hwnd, Window.WndProc, Message.Message, Message.WParam, Message.LParam))
            {
                ulong FallbackResult = Win32kHelper.DispatchMessage(Instance, Message);
                Instance.SetRawSyscallReturn(FallbackResult);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
