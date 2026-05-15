using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtResumeThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong PreviousSuspendCountPtr = Instance.WinHelper.GetArg64(1);

            EmulatedThread TargetThread = null;
            if (ThreadHandle == 0xFFFFFFFFFFFFFFFEUL)
                TargetThread = Instance.CurrentThread;
            else
                TargetThread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
            if (TargetThread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (PreviousSuspendCountPtr != 0)
            {
                if (!Instance.IsRegionMapped(PreviousSuspendCountPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PreviousSuspendCountPtr, (uint)TargetThread.SuspendCount);
            }

            if (TargetThread.SuspendCount > 0)
                TargetThread.SuspendCount--;

            if (TargetThread.SuspendCount == 0)
            {
                if (TargetThread.State == EmulatedThreadState.Suspended)
                {
                    if (TargetThread.WaitActive)
                        TargetThread.State = EmulatedThreadState.Waiting;
                    else
                        TargetThread.State = EmulatedThreadState.Ready;
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
