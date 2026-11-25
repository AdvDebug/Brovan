using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReleaseMutant : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance)
        {
            ulong MutantHandle = Instance.WinHelper.GetArg(0);
            WinMutex? Mutex = LookUpMutant(Instance, MutantHandle);
            if (Mutex == null)
                return WinSyscallDomain.KernelLock;

            Instance.WinHelper.SetResolvedObject(MutantHandle, Mutex);
            return WinSyscallDomain.Scheduler;
        }

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

        private static WinMutex? LookUpMutant(BinaryEmulator Instance, ulong MutantHandle) =>
            Instance.WinHelper.HandleManager.GetObjectByHandle<WinMutex>(MutantHandle);

        private static NTSTATUS HandleReleaseMutant(BinaryEmulator Instance, ulong MutantHandle, ulong PreviousCountPtr)
        {
            if (PreviousCountPtr != 0 && !Instance._emulator.IsRangeMapped(PreviousCountPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinMutex? Mutex = Instance.WinHelper.TakeResolvedObject<WinMutex>(MutantHandle) ?? LookUpMutant(Instance, MutantHandle);
            if (Mutex == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            uint CurrentThreadId = (uint)Instance.CurrentThreadId;
            int PreviousCount;
            using (Mutex.EnterStateScope())
            {
                if (Mutex.OwnerThreadId != CurrentThreadId || Mutex.RecursionCount <= 0)
                    return NTSTATUS.STATUS_MUTANT_NOT_OWNED;

                PreviousCount = Mutex.SignalState;
                Mutex.RecursionCount--;
                if (Mutex.RecursionCount == 0)
                {
                    Mutex.OwnerThreadId = 0;
                    Mutex.Signaled = true;
                    Mutex.Abandoned = false;
                }
            }

            // NT ignores a fault on this write once the mutant has changed.
            if (PreviousCountPtr != 0)
                Instance._emulator.WriteMemory(PreviousCountPtr, PreviousCount);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
