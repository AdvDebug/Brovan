using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIQueryVideoMemoryInfo : IWinSyscall
    {
        private const int QueryVideoMemoryInfoSize = 56;

        // hProcess leads the structure and is a HANDLE, so hAdapter and the segment group sit after it.
        private const int OffsetBudget = 16;
        private const int OffsetCurrentUsage = 24;
        private const int OffsetCurrentReservation = 32;
        private const int OffsetAvailableForReservation = 40;

        private const uint SegmentGroupLocal = 0;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, QueryVideoMemoryInfoSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong OffsetAdapter = (ulong)Instance.WinHelper.PointerSize;

            if (!Win32kDxgk.IsAdapter(Instance.ReadMemoryUInt(ArgumentsPtr + OffsetAdapter)))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint SegmentGroup = Instance.ReadMemoryUInt(ArgumentsPtr + OffsetAdapter + 4);
            ulong Budget = SegmentGroup == SegmentGroupLocal
                ? Win32kDxgk.DedicatedVideoMemory
                : Win32kDxgk.SharedSystemMemory;

            Instance._emulator.WriteMemory(ArgumentsPtr + OffsetBudget, Budget, 8);
            Instance._emulator.WriteMemory(ArgumentsPtr + OffsetCurrentUsage, 0UL, 8);
            Instance._emulator.WriteMemory(ArgumentsPtr + OffsetCurrentReservation, 0UL, 8);
            Instance._emulator.WriteMemory(ArgumentsPtr + OffsetAvailableForReservation, Budget / 2, 8);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
