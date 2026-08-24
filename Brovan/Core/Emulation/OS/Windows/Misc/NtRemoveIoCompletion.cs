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

            WinIoCompletion Completion = Instance.WinHelper.HandleManager.GetObjectByHandle<WinIoCompletion>(IoCompletionHandle);
            if (Completion == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitCompleted)
            {
                NTSTATUS Completed = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;

                if (Completed == NTSTATUS.STATUS_TIMEOUT)
                    return Completed;
            }

            Instance.MaterializeSignaledWaitPackets(IoCompletionHandle);

            if (Completion.PendingCount > 0)
            {
                WinIoCompletionEntry Entry = Completion.Take();
                Instance.ReleaseWaitCompletionPacket(Entry);

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
                long NewDeadline = Instance.WinHelper.ParseRelativeDeadlineMs(TimeoutPtr);
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
                State.IoCompletionWaitActive = true;
                State.IoCompletionHandle = IoCompletionHandle;
                State.IoCompletionKeyContextPtr = KeyContextPtr;
                State.IoCompletionApcContextPtr = ApcContextPtr;
                State.IoCompletionIoStatusBlockPtr = IoStatusBlockPtr;
                State.IoCompletionReservedEntry = null;
            }

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = false;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
