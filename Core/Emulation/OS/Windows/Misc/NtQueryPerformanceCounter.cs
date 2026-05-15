using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryPerformanceCounter : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong PerformanceCounterPtr = Instance.WinHelper.GetArg64(0);
                ulong PerformanceFrequencyPtr = Instance.WinHelper.GetArg64(1);

                if (!Instance.IsRegionMapped(PerformanceCounterPtr, 8))
                {
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (PerformanceCounterPtr != 0)
                {
                    ulong CounterValue = (ulong)System.Diagnostics.Stopwatch.GetTimestamp();
                    Instance._emulator.WriteMemory(PerformanceCounterPtr, CounterValue, 0);
                }

                if (PerformanceFrequencyPtr != 0 && !Instance.IsRegionMapped(PerformanceFrequencyPtr, 8))
                {
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
                else
                {
                    Instance._emulator.WriteMemory(PerformanceFrequencyPtr, 10000000UL);
                }
                return NTSTATUS.STATUS_SUCCESS;
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                uint PerformanceCounterPtr = Instance.WinHelper.GetArg32(0);
                uint PerformanceFrequencyPtr = Instance.WinHelper.GetArg32(1);

                if (!Instance.IsRegionMapped(PerformanceCounterPtr, 8))
                {
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (PerformanceCounterPtr != 0)
                {
                    ulong CounterValue = (ulong)System.Diagnostics.Stopwatch.GetTimestamp();
                    Instance._emulator.WriteMemory(PerformanceCounterPtr, CounterValue, 0);
                }

                if (PerformanceFrequencyPtr != 0 && !Instance.IsRegionMapped(PerformanceFrequencyPtr, 8))
                {
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
                else
                {
                    Instance._emulator.WriteMemory(PerformanceFrequencyPtr, 10000000UL);
                }
                return NTSTATUS.STATUS_SUCCESS;
            }
            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }
    }
}
