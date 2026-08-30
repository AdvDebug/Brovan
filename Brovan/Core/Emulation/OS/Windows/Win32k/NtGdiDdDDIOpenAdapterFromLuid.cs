using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIOpenAdapterFromLuid : IWinSyscall
    {
        private const int OpenAdapterFromLuidSize = 12;
        private const int OffsetHandle = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, OpenAdapterFromLuidSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint LowPart = Instance.ReadMemoryUInt(ArgumentsPtr);
            int HighPart = unchecked((int)Instance.ReadMemoryUInt(ArgumentsPtr + 4));

            if (!Win32kDxgk.MatchesLuid(LowPart, HighPart))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance._emulator.WriteMemory(ArgumentsPtr + OffsetHandle, Win32kDxgk.AdapterHandle, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
