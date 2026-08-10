namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryTimerResolution : IWinSyscall
    {
        private const uint CoarsestResolution = 156250;
        private const uint FinestResolution = 5000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong MinimumResolutionPtr = Instance.WinHelper.GetArg(0);
            ulong MaximumResolutionPtr = Instance.WinHelper.GetArg(1);
            ulong CurrentResolutionPtr = Instance.WinHelper.GetArg(2);

            if (MinimumResolutionPtr == 0 || MaximumResolutionPtr == 0 || CurrentResolutionPtr == 0
                || !Instance.IsRegionMapped(MinimumResolutionPtr, 4)
                || !Instance.IsRegionMapped(MaximumResolutionPtr, 4)
                || !Instance.IsRegionMapped(CurrentResolutionPtr, 4))
            {
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Instance._emulator.WriteMemory(MinimumResolutionPtr, CoarsestResolution, 4);
            Instance._emulator.WriteMemory(MaximumResolutionPtr, FinestResolution, 4);
            Instance._emulator.WriteMemory(CurrentResolutionPtr, CoarsestResolution, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
