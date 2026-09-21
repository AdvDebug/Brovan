namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimerResolution : IWinSyscall
    {
        private const uint CoarsestResolution = 156250;
        private const uint FinestResolution = 5000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint DesiredResolution = (uint)Instance.WinHelper.GetArg(0);
            bool SetResolution = Instance.WinHelper.GetArg(1) != 0;
            ulong CurrentResolutionPtr = Instance.WinHelper.GetArg(2);

            if (CurrentResolutionPtr == 0 || !Instance.IsRegionMapped(CurrentResolutionPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Granted = SetResolution
                ? System.Math.Clamp(DesiredResolution, FinestResolution, CoarsestResolution)
                : CoarsestResolution;

            Instance._emulator.WriteMemory(CurrentResolutionPtr, Granted, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
