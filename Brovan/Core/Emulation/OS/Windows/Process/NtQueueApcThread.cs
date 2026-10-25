using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueueApcThread : IWinSyscall
    {
        internal static EmulatedThread GetTargetThread(BinaryEmulator Instance, ulong ThreadHandle)
        {
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
                return Instance.CurrentThread;

            return Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
        }

        internal static NTSTATUS Queue(BinaryEmulator Instance, EmulatedThread Thread, uint ApcFlags, ulong ApcRoutine, ulong ApcArgument1, ulong ApcArgument2, ulong ApcArgument3)
        {
            return Queue(Instance, Thread, new WinPendingUserApc
            {
                Flags = ApcFlags,
                ApcRoutine = ApcRoutine,
                ApcArgument1 = ApcArgument1,
                ApcArgument2 = ApcArgument2,
                ApcArgument3 = ApcArgument3
            });
        }

        internal static NTSTATUS Queue(BinaryEmulator Instance, EmulatedThread Thread, WinPendingUserApc Apc)
        {
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Thread.State == EmulatedThreadState.Terminated)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            State.PendingUserApcs.Add(Apc);

            // A queued APC makes the target runnable through HasPendingGuestWork even when it stays Waiting.
            Instance.WakeSignal.Bump();

            bool SpecialApc = Apc.IsSpecial;
            bool AlertableWait = Thread.WaitActive && State.WaitAlertable;

            if (AlertableWait)
                State.ApcAlertable = true;

            if ((SpecialApc || AlertableWait) && Thread.State == EmulatedThreadState.Waiting)
            {
                Instance.UnfileWait(Thread);
                Thread.State = EmulatedThreadState.Ready;
            }

            if (SpecialApc || AlertableWait)
            {
                if (Instance.CurrentThreadId == (int)Thread.ThreadId)
                    Instance._emulator.StopEmulation();
                else
                {
                    Instance._emulator.StopThread(Thread.ThreadId);
                    Instance.YieldSliceAfterWake(Thread);
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong ApcRoutine = Instance.WinHelper.GetArg(1);
            ulong ApcArgument1 = Instance.WinHelper.GetArg(2);
            ulong ApcArgument2 = Instance.WinHelper.GetArg(3);
            ulong ApcArgument3 = Instance.WinHelper.GetArg(4);

            EmulatedThread Thread = GetTargetThread(Instance, ThreadHandle);
            return Queue(Instance, Thread, 0, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        }
    }
}