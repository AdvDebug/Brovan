using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueueApcThread : IWinSyscall
    {
        internal static EmulatedThread GetTargetThread(BinaryEmulator Instance, ulong ThreadHandle)
        {
            if (ThreadHandle == HandleManager.CurrentThread)
                return Instance.CurrentThread;

            return Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
        }

        internal static NTSTATUS Queue(BinaryEmulator Instance, EmulatedThread Thread, uint ApcFlags, ulong ApcRoutine, ulong ApcArgument1, ulong ApcArgument2, ulong ApcArgument3)
        {
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (WinEmulatedThread.GetState(Thread).PendingUserApcs == null)
                WinEmulatedThread.GetState(Thread).PendingUserApcs = new List<WinPendingUserApc>();

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            State.PendingUserApcs.Add(new WinPendingUserApc
            {
                Flags = ApcFlags,
                ApcRoutine = ApcRoutine,
                ApcArgument1 = ApcArgument1,
                ApcArgument2 = ApcArgument2,
                ApcArgument3 = ApcArgument3
            });

            bool SpecialApc = (ApcFlags & WinPendingUserApc.SpecialUserApc) != 0;
            bool AlertableWait = Thread.WaitActive && State.WaitAlertable;

            if (AlertableWait)
                State.ApcAlertable = true;

            if ((SpecialApc || AlertableWait) && Thread.State == EmulatedThreadState.Waiting)
                Thread.State = EmulatedThreadState.Ready;

            if (SpecialApc || AlertableWait)
                Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong ApcRoutine = Instance.WinHelper.GetArg64(1);
            ulong ApcArgument1 = Instance.WinHelper.GetArg64(2);
            ulong ApcArgument2 = Instance.WinHelper.GetArg64(3);
            ulong ApcArgument3 = Instance.WinHelper.GetArg64(4);

            EmulatedThread Thread = GetTargetThread(Instance, ThreadHandle);
            return Queue(Instance, Thread, 0, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        }
    }
}