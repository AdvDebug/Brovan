namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWorkerFactoryWorkerReady : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg(0);
            return WorkerFactoryHelper.MarkWorkerReady(Instance, WorkerFactoryHandle);
        }
    }
}