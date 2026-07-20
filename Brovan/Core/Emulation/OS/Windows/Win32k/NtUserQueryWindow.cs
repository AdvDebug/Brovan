using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserQueryWindow : IWinSyscall
    {
        private const uint QUERY_WINDOW_UNIQUE_PROCESS_ID = 0x00;
        private const uint QUERY_WINDOW_UNIQUE_THREAD_ID = 0x01;
        private const uint QUERY_WINDOW_ACTIVE = 0x02;
        private const uint QUERY_WINDOW_FOCUS = 0x03;
        private const uint QUERY_WINDOW_ISHUNG = 0x04;
        private const uint QUERY_WINDOW_REAL_ID = 0x05;
        private const uint QUERY_WINDOW_FOREGROUND = 0x06;
        private const uint QUERY_WINDOW_DEFAULT_IME = 0x07;
        private const uint QUERY_WINDOW_DEFAULT_ICONTEXT = 0x08;
        private const uint QUERY_WINDOW_ACTIVE_IME = 0x09;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Index = (uint)Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Result = 0;

            switch (Index)
            {
                case QUERY_WINDOW_UNIQUE_PROCESS_ID:
                    Result = Instance.WinHelper.PID;
                    break;

                case QUERY_WINDOW_UNIQUE_THREAD_ID:
                    Result = Window.OwnerThreadId;
                    break;

                case QUERY_WINDOW_ACTIVE:
                    Result = Instance.WinHelper.ActiveWindow;
                    break;

                case QUERY_WINDOW_FOCUS:
                    Result = Instance.WinHelper.FocusWindow;
                    break;

                case QUERY_WINDOW_ISHUNG:
                    Result = 0;
                    break;

                case QUERY_WINDOW_REAL_ID:
                    Result = Instance.WinHelper.PID;
                    break;

                case QUERY_WINDOW_FOREGROUND:
                    Result = Instance.WinHelper.GetForegroundWindow() == Hwnd ? 1ul : 0ul;
                    break;

                case QUERY_WINDOW_DEFAULT_IME:
                case QUERY_WINDOW_DEFAULT_ICONTEXT:
                case QUERY_WINDOW_ACTIVE_IME:
                default:
                    Result = 0;
                    break;
            }

            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}