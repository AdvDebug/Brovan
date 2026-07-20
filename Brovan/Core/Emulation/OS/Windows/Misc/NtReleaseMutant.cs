using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReleaseMutant : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong MutantHandle = Instance.WinHelper.GetArg(0);
                ulong PreviousCountPtr = Instance.WinHelper.GetArg(1);

                return HandleReleaseMutant(Instance, MutantHandle, PreviousCountPtr);
            }


            uint MutantHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint PreviousCountPtr32 = (uint)Instance.WinHelper.GetArg(1);

            return HandleReleaseMutant(Instance, MutantHandle32, PreviousCountPtr32);
        }

        private static NTSTATUS HandleReleaseMutant(BinaryEmulator Instance, ulong MutantHandle, ulong PreviousCountPtr)
        {
            if (PreviousCountPtr != 0 && !Instance.IsRegionMapped(PreviousCountPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinMutex Mutex = Instance.WinHelper.HandleManager.GetObjectByHandle<WinMutex>(MutantHandle);
            if (Mutex == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            uint CurrentThreadId = (uint)Instance.CurrentThreadId;
            if (Mutex.OwnerThreadId != CurrentThreadId || Mutex.RecursionCount <= 0)
                return NTSTATUS.STATUS_MUTANT_NOT_OWNED;

            int PreviousCount = Mutex.SignalState;
            Mutex.RecursionCount--;
            if (Mutex.RecursionCount == 0)
            {
                Mutex.OwnerThreadId = 0;
                Mutex.Signaled = true;
                Mutex.Abandoned = false;
            }

            if (PreviousCountPtr != 0)
            {
                if (!Instance._emulator.WriteMemory(PreviousCountPtr, PreviousCount))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
