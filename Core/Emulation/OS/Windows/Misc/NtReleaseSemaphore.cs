using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReleaseSemaphore : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong SemaphoreHandle = Instance.WinHelper.GetArg64(0);
                int ReleaseCount = (int)Instance.WinHelper.GetArg64(1, true);
                ulong PreviousCountPtr = Instance.WinHelper.GetArg64(2);

                return HandleReleaseSemaphore(Instance, SemaphoreHandle, ReleaseCount, PreviousCountPtr);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint SemaphoreHandle32 = Instance.ReadMemoryUInt(SP + 4);
            int ReleaseCount32 = (int)Instance.ReadMemoryUInt(SP + 8);
            uint PreviousCountPtr32 = Instance.ReadMemoryUInt(SP + 12);

            return HandleReleaseSemaphore(Instance, SemaphoreHandle32, ReleaseCount32, PreviousCountPtr32);
        }

        private static NTSTATUS HandleReleaseSemaphore(BinaryEmulator Instance, ulong SemaphoreHandle, int ReleaseCount, ulong PreviousCountPtr)
        {
            if (PreviousCountPtr != 0 && !Instance.IsRegionMapped(PreviousCountPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReleaseCount <= 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinSemaphore Semaphore = Instance.WinHelper.GetSemaphoreByHandle(SemaphoreHandle, AccessMask.SemaphoreModifyState);
            if (Semaphore == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Semaphore.CurrentCount > Semaphore.MaximumCount - ReleaseCount)
                return NTSTATUS.STATUS_SEMAPHORE_LIMIT_EXCEEDED;

            int PreviousCount = Semaphore.CurrentCount;
            Semaphore.CurrentCount += ReleaseCount;

            if (PreviousCountPtr != 0)
            {
                if (!Instance._emulator.WriteMemory(PreviousCountPtr, PreviousCount))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (PreviousCount == 0 && Semaphore.CurrentCount > 0 && Instance.WakeWorkerFactoryWaitersForObject(SemaphoreHandle))
                Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
