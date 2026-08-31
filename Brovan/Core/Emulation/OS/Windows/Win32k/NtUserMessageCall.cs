using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMessageCall : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Message = (uint)Instance.WinHelper.GetArg(1);
            ulong WParam = Instance.WinHelper.GetArg(2);
            ulong LParam = Instance.WinHelper.GetArg(3);
            ulong XParam = Instance.WinHelper.GetArg(4);
            uint FunctionId = (uint)Instance.WinHelper.GetArg(5);
            ulong Flags = (uint)Instance.WinHelper.GetArg(6);
            bool Ansi = (XParam & 1) != 0 || (Flags & 1) != 0;

            if ((Message & 0xFFFE0000u) != 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Win32kHelper.IsSendMessageFunction(FunctionId))
            {
                WinWindow Target = Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Hwnd);

                // A window procedure only ever runs on the thread that owns the window.
                bool OwnedHere = Target != null && Target.OwnerThreadId == (Instance.CurrentThread?.ThreadId ?? 0);
                if (OwnedHere)
                {
                    ulong WndProc = Target.WndProc;
                    if (Ansi)
                    {
                        if (Instance.WinHelper.BeginClientPfnFetch())
                            return NTSTATUS.STATUS_SUCCESS;

                        WndProc = Instance.WinHelper.GetAnsiWindowProc(WndProc, Instance.WinHelper.GetWindowClassFunctionId(Target));
                    }

                    if (Win32kHelper.InvokeWindowProc(Instance, Hwnd, WndProc, Message, WParam, LParam))
                        return NTSTATUS.STATUS_SUCCESS;
                }
            }

            ulong Result = Win32kHelper.HandleMessageCall(Instance, Hwnd, Message, WParam, LParam, Ansi);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
