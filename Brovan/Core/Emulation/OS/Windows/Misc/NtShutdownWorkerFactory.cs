using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtShutdownWorkerFactory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg(0);
            ulong PendingWorkerCountPtr = Instance.WinHelper.GetArg(1);

            WinWorkerFactory Factory = WorkerFactoryHelper.GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Factory.Shutdown = true;
            Factory.PendingReleaseCount = 0;
            Factory.ReleasePending = false;
            Factory.WorkerThreads.Clear();

            if (PendingWorkerCountPtr != 0)
            {
                if (!Instance.IsRegionMapped(PendingWorkerCountPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PendingWorkerCountPtr, 0u, 4);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
