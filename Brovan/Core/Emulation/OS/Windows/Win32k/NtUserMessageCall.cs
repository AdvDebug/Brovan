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
            ushort FunctionId = Win32kHelper.MaskFunctionId((uint)Instance.WinHelper.GetArg(5));
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

                    if (FunctionId == Win32kHelper.FnidSendMessageCallProc)
                    {
                        if (!Instance.WinHelper.TryGetCallProc(XParam, out WndProc))
                            WndProc = XParam;
                    }
                    else if (Ansi)
                    {
                        if (Instance.WinHelper.BeginClientPfnFetch())
                            return NTSTATUS.STATUS_SUCCESS;

                        WndProc = Instance.WinHelper.GetAnsiWindowProc(WndProc, Instance.WinHelper.GetWindowClassFunctionId(Target));
                    }

                    if (FunctionId == Win32kHelper.FnidSendMessageCallback)
                    {
                        // NT: the call returns TRUE and hands the procedure's result to the callback, if there is one.
                        if (!Instance.WinHelper.TryReadPointer(XParam, out ulong Callback)
                            || !Instance.WinHelper.TryReadPointer(XParam + (ulong)Instance.WinHelper.PointerSize, out ulong Data))
                        {
                            return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);
                        }

                        WinSendMessageCallback Continuation = Callback == 0 ? null
                            : new WinSendMessageCallback { Hwnd = Hwnd, Message = Message, Callback = Callback, Data = Data };
                        if (Win32kHelper.InvokeWindowProc(Instance, Hwnd, WndProc, Message, WParam, LParam, Continuation, DeferredSyscallResult: 1))
                            return NTSTATUS.STATUS_SUCCESS;
                    }
                    // NT: SendNotifyMessage is SendMessageCallback with no callback, so it returns TRUE too.
                    else if (Win32kHelper.InvokeWindowProc(Instance, Hwnd, WndProc, Message, WParam, LParam,
                        DeferredSyscallResult: FunctionId == Win32kHelper.FnidSendNotifyMessage ? 1UL : null))
                    {
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                }
            }

            ulong Result = Win32kHelper.HandleMessageCall(Instance, Hwnd, Message, WParam, LParam, Ansi, out bool Deferred);
            if ((FunctionId == Win32kHelper.FnidSendMessageCallback || FunctionId == Win32kHelper.FnidSendNotifyMessage) && Instance.WinHelper.GetWindow(Hwnd) != null)
                Result = 1;

            if (!Deferred)
                Instance.SetRawSyscallReturn(Result);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
