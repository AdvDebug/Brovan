using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtRemoveIoCompletion : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong IoCompletionHandle = Instance.WinHelper.GetArg(0);
            ulong KeyContextPtr = Instance.WinHelper.GetArg(1);
            ulong ApcContextPtr = Instance.WinHelper.GetArg(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(3);
            ulong TimeoutPtr = Instance.WinHelper.GetArg(4);

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (KeyContextPtr == 0 || ApcContextPtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(KeyContextPtr, PointerSize)
                || !Instance.IsRegionMapped(ApcContextPtr, PointerSize)
                || !Instance.IsRegionMapped(IoStatusBlockPtr, PointerSize * 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            long? Timeout = null;
            if (!Thread.WaitActive && !Instance.WinHelper.TryReadTimeout(TimeoutPtr, out Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS HandleStatus = Instance.WinHelper.ResolveIoCompletionHandle(IoCompletionHandle, out WinIoCompletion Completion);
            if (HandleStatus != NTSTATUS.STATUS_SUCCESS)
                return HandleStatus;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            State.BoundIoCompletion = Completion;
            if (State.WaitCompleted)
            {
                NTSTATUS Completed = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;

                if (Completed == NTSTATUS.STATUS_TIMEOUT)
                    return Completed;
            }

            Instance.MaterializeSignaledWaitPackets(IoCompletionHandle);

            List<WinIoCompletionEntry> Taken = State.IoCompletionReservedEntries;
            Taken.Clear();
            Instance.TakeIoCompletionEntries(Completion, 1, Taken);
            if (Taken.Count > 0)
            {
                WinIoCompletionEntry Entry = Taken[0];
                Taken.Clear();

                if (Thread.WaitActive)
                    Instance.WinHelper.ClearWaitState(Thread);

                Instance.WinHelper.WritePointer(KeyContextPtr, Entry.KeyContext);
                Instance.WinHelper.WritePointer(ApcContextPtr, Entry.ApcContext);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Entry.IoStatus, Entry.IoStatusInformation);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Thread.WaitActive)
            {
                if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
                {
                    Instance.WinHelper.ClearWaitState(Thread);
                    return NTSTATUS.STATUS_TIMEOUT;
                }
            }
            else
            {
                long NewDeadline = Instance.WinHelper.ParseRelativeDeadlineMs(Timeout);
                if (NewDeadline == Instance.EmulatedTickCount64)
                    return NTSTATUS.STATUS_TIMEOUT;

                Thread.WaitActive = true;
                Thread.WaitHandles = new List<ulong> { IoCompletionHandle };
                Thread.WaitAll = true;
                Thread.WaitDeadline = NewDeadline;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_PENDING;
                State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
                State.WaitReturnRIP = State.WaitResumeRIP + 2;
                State.WaitAlertable = false;
                State.ResetIoCompletionWait();
                State.IoCompletionWaitActive = true;
                State.IoCompletionHandle = IoCompletionHandle;
                State.IoCompletionKeyContextPtr = KeyContextPtr;
                State.IoCompletionApcContextPtr = ApcContextPtr;
                State.IoCompletionIoStatusBlockPtr = IoStatusBlockPtr;
                State.IoCompletionMaxEntries = 1;
            }

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = false;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
