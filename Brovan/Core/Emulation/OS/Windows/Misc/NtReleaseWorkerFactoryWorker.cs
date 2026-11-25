using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReleaseWorkerFactoryWorker : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg(0);

            WinWorkerFactory Factory = WorkerFactoryHelper.GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            using (Factory.EnterStateScope())
            {
                if (Factory.PendingReleaseCount == uint.MaxValue)
                    return NTSTATUS.STATUS_UNSUCCESSFUL;

                Factory.PendingReleaseCount++;
                if (!Factory.ReleasePending)
                {
                    Factory.ReleasePending = true;
                    WorkerFactoryHelper.EnqueueReleaseCompletion(Factory);
                }
            }

            WorkerFactoryHelper.EnsureWorkerThreads(Instance, Factory);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
