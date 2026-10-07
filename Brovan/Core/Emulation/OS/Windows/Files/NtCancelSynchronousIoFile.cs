using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtCancelSynchronousIoFile : IWinSyscall
    {
        // NT: IopCancelSynchronousIrpsForThread. The IO_STATUS_BLOCK is probed first and written for NOT_FOUND too.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong IoRequestToCancel = Instance.WinHelper.GetArg(1);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(2);

            if (!Instance.IsMemoryRangeMapped(IoStatusBlockPtr, (ulong)Instance.WinHelper.PointerSize * 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            EmulatedThread Thread = WindowsThreadContext64.ResolveThread(Instance, ThreadHandle);
            IHandleObject Object = Thread == null ? Instance.WinHelper.HandleManager.GetObjectByHandle(ThreadHandle) : null;
            if (Thread == null && Object == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Thread == null && Object is not WinRemoteThread)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (!WindowsThreadContext64.HasThreadAccess(Instance, ThreadHandle, AccessMask.ThreadTerminate))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            // The thread runs in another emulator, which this one cannot reach.
            if (Thread == null)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            NTSTATUS Status = Cancel(Instance, Thread, IoRequestToCancel) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NOT_FOUND;
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
            return Status;
        }

        private static bool Cancel(BinaryEmulator Instance, EmulatedThread Thread, ulong IoRequestToCancel)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State == null || Thread.State == EmulatedThreadState.Terminated)
                return false;

            ParkedIoRequest Request = State.IoRequest;
            if (Thread.WaitActive && Request != null)
            {
                if (Request.Completed)
                    return false;

                int ThreadId = (int)Thread.ThreadId;
                int Cancelled = Instance.WinHelper.PipeRequests.Cancel(Instance, Request.File, IoRequestToCancel, ThreadId) +
                    Instance.WinHelper.AfdRequests.Cancel(Instance, Request.File, IoRequestToCancel, ThreadId);
                return Cancelled != 0;
            }

            // Between two runs of a retried call the thread still waits for the I/O.
            bool InCall = (Thread.WaitActive && State.RetrySyscallActive) || State.SyncIoBetweenRetries;
            if (!InCall || State.SyncIoCancelled || State.SyncIo is not WinPendingIo Io)
                return false;

            if (IoRequestToCancel != 0 && Io.IoStatusBlock != IoRequestToCancel)
                return false;

            State.SyncIoCancelled = true;
            Instance.WinHelper.CompletePendingIo(in Io, NTSTATUS.STATUS_CANCELLED, 0);
            Instance.WakeSignal.Bump();
            return true;
        }
    }
}
