using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetMessage : IWinSyscall
    {
        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);

            Win32kHelper.DrainHostEvents(Instance);
            if (Win32kHelper.TryGetMessage(Instance, State.GetMessageHwndFilter, State.GetMessageMinMessage, State.GetMessageMaxMessage, Win32kHelper.QS_ALLINPUT, true, Thread.ThreadId, out Win32kMessage Message))
            {
                ulong MessagePtr = State.GetMessageMessagePtr;
                Instance.WinHelper.ClearWaitState(Thread);
                return CompleteRead(Instance, MessagePtr, Message, State);
            }

            Thread.WaitDeadline = Win32kHelper.GetNextTimerDue(Instance, State.GetMessageHwndFilter, Thread.ThreadId, State.GetMessageMinMessage, State.GetMessageMaxMessage);
            Thread.State = EmulatedThreadState.Waiting;
            WinEmulatedThread.GetState(Thread).ApcAlertable = WinEmulatedThread.GetState(Thread).WaitAlertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        private static NTSTATUS CompleteRead(BinaryEmulator Instance, ulong MessagePtr, in Win32kMessage Message, WindowsThreadState State)
        {
            if (!Win32kHelper.TryCompleteRead(Instance, MessagePtr, Message, State, Removed: true, out bool CallbackEntered))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (CallbackEntered || (Message.Message != Win32kHelper.WM_QUIT && Win32kHelper.TryDeliverWindowPosChanged(Instance, 1)))
                return NTSTATUS.STATUS_SUCCESS;

            Instance.SetRawSyscallReturn(Message.Message == Win32kHelper.WM_QUIT ? 0ul : 1ul);
            return NTSTATUS.STATUS_SUCCESS;
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
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            Win32kHelper.DrainHostEvents(Instance);

            // NT: a sent message runs inside GetMessage, which then goes on waiting.
            ulong SyscallRip = Instance.WinHelper.GetSyscallRip();
            if (Win32kHelper.ReceiveNotification(Instance, SyscallRip))
                return NTSTATUS.STATUS_SUCCESS;

            if (Win32kHelper.TryGetMessage(Instance, HwndFilter, MinMessage, MaxMessage, Win32kHelper.QS_ALLINPUT, true, Thread.ThreadId, out Win32kMessage Message))
                return CompleteRead(Instance, MessagePtr, Message, State);

            if (Win32kHelper.TryDeliverWindowPosChanged(Instance, 0, SyscallRip))
                return NTSTATUS.STATUS_SUCCESS;

            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = Win32kHelper.GetNextTimerDue(Instance, HwndFilter, Thread.ThreadId, MinMessage, MaxMessage);
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = SyscallRip;
            State.WaitReturnRIP = State.WaitResumeRIP + 2;
            State.RetrySyscallNumber = Instance.WinHelper.ReadSyscallNumber();
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
