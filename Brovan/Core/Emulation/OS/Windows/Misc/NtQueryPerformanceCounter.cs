using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryPerformanceCounter : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PerformanceCounterPtr = Instance.WinHelper.GetArg(0);
            ulong PerformanceFrequencyPtr = Instance.WinHelper.GetArg(1);

            if (PerformanceCounterPtr == 0 || !Instance.IsRegionMapped(PerformanceCounterPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(PerformanceCounterPtr, WinSysHelper.QueryPerformanceCounterValue(), 8);

            if (PerformanceFrequencyPtr != 0)
            {
                if (!Instance.IsRegionMapped(PerformanceFrequencyPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PerformanceFrequencyPtr, (ulong)KuserSharedDataManager.QpcFrequency, 8);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
