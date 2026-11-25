using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForSingleObject : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            if (State == null)
                return WinSyscallDomain.KernelLock;

            if (Thread.WaitActive)
                return State.WaitNeedsKernelLock ? WinSyscallDomain.KernelLock : WinSyscallDomain.Scheduler;

            IHandleObject Obj = Instance.WinHelper.HandleManager.GetObjectByHandle(Instance.WinHelper.GetArg(0));
            if (Obj == null)
                return WinSyscallDomain.KernelLock;

            State.ClearWaitObjects();
            Instance.AddWaitObject(State, Obj);
            return Instance.KeepResolvedWait(State);
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Handle = Instance.WinHelper.GetArg(0);
            bool Alertable = (byte)Instance.WinHelper.GetArg(1) != 0;
            ulong TimeoutPtr = Instance.WinHelper.GetArg(2);

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
                return Instance.ContinueObjectWait(Thread, State);

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TakeResolvedWait())
            {
                IHandleObject Obj = Instance.WinHelper.HandleManager.GetObjectByHandle(Handle);
                if (Obj == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                State.ClearWaitObjects();
                Instance.AddWaitObject(State, Obj);
            }

            return Instance.WaitForObjects(Thread, State, WaitAll: true, Alertable, Timeout);
        }
    }
}
