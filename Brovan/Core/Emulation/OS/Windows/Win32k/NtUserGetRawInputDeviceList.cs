using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetRawInputDeviceList : IWinSyscall
    {
        private const uint RimTypeMouse = 0;
        private const uint RimTypeKeyboard = 1;

        private static readonly (ulong Handle, uint Type)[] Devices =
        {
            (0x00010001, RimTypeMouse),
            (0x00010002, RimTypeKeyboard),
        };

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ListPtr = Instance.WinHelper.GetArg(0);
            ulong CountPtr = Instance.WinHelper.GetArg(1);
            uint EntrySizeArg = (uint)Instance.WinHelper.GetArg(2);

            uint EntrySize = Instance.IsX86Guest ? 8u : 16u;

            if (EntrySizeArg != EntrySize || CountPtr == 0 || !Instance.IsRegionMapped(CountPtr, 4))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(uint.MaxValue);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Count = (uint)Devices.Length;

            if (ListPtr == 0)
            {
                Instance._emulator.WriteMemory(CountPtr, Count, 4);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Capacity = Instance.ReadMemoryUInt(CountPtr);
            if (Capacity < Count)
            {
                Instance._emulator.WriteMemory(CountPtr, Count, 4);
                Instance.SetLastWinError(Win32kHelper.ERROR_INSUFFICIENT_BUFFER);
                Instance.SetRawSyscallReturn(uint.MaxValue);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(ListPtr, Count * EntrySize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(uint.MaxValue);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (uint Index = 0; Index < Count; Index++)
            {
                ulong Entry = ListPtr + Index * EntrySize;
                Instance._emulator.WriteMemory(Entry, Devices[Index].Handle, Instance.IsX86Guest ? 4u : 8u);
                Instance._emulator.WriteMemory(Entry + (Instance.IsX86Guest ? 4ul : 8ul), Devices[Index].Type, 4);
            }

            Instance.SetRawSyscallReturn(Count);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
