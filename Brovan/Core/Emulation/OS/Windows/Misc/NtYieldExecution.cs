using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtYieldExecution : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return Yield(Instance, Thread);
        }

        internal static NTSTATUS Yield(BinaryEmulator Instance, EmulatedThread Thread)
        {
            NTSTATUS Status = Instance.HasThreadReadyForYield() ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NO_YIELD_PERFORMED;

            // The slice ends also when no thread is ready, because host I/O is served only between slices.
            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return Status;
        }
    }
}
