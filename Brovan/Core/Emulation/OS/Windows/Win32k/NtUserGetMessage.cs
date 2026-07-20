using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetMessage : IWinSyscall
    {
        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);

            if (Win32kHelper.TryGetMessage(Instance, State.GetMessageHwndFilter, State.GetMessageMinMessage, State.GetMessageMaxMessage, true, out Win32kMessage Message))
            {
                bool Written = Win32kHelper.WriteMessage(Instance, State.GetMessageMessagePtr, Message);
                Instance.WinHelper.ClearWaitState(Thread);

                if (!Written)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn(Message.Message == Win32kHelper.WM_QUIT ? 0ul : 1ul);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Thread.State = EmulatedThreadState.Waiting;
            WinEmulatedThread.GetState(Thread).ApcAlertable = WinEmulatedThread.GetState(Thread).WaitAlertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong MessagePtr = Instance.WinHelper.GetArg(0);
            ulong HwndFilter = Instance.WinHelper.GetArg(1);
            uint MinMessage = (uint)Instance.WinHelper.GetArg(2);
            uint MaxMessage = (uint)Instance.WinHelper.GetArg(3);

            if (MessagePtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitCompleted)
            {
                NTSTATUS Status = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (Thread.WaitActive)
                return ContinueWait(Instance, Thread);

            if (!Win32kHelper.IsKnownWindow(Instance, HwndFilter))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Win32kHelper.TryGetMessage(Instance, HwndFilter, MinMessage, MaxMessage, true, out Win32kMessage Message))
            {
                if (!Win32kHelper.WriteMessage(Instance, MessagePtr, Message))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn(Message.Message == Win32kHelper.WM_QUIT ? 0ul : 1ul);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = -1;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
            State.WaitReturnRIP = State.WaitResumeRIP + 2;
            State.WaitAlertable = false;
            State.GetMessageWaitActive = true;
            State.GetMessageMessagePtr = MessagePtr;
            State.GetMessageHwndFilter = HwndFilter;
            State.GetMessageMinMessage = MinMessage;
            State.GetMessageMaxMessage = MaxMessage;

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = false;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_PENDING;
        }
    }
}
