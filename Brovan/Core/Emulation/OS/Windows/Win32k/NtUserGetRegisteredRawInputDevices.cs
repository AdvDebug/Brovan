using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetRegisteredRawInputDevices : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DevicesPtr = Instance.WinHelper.GetArg(0);
            ulong CountPtr = Instance.WinHelper.GetArg(1);
            uint EntrySizeArg = (uint)Instance.WinHelper.GetArg(2);

            uint EntrySize = Instance.IsX86Guest ? 12u : 16u;

            if (EntrySizeArg != EntrySize || CountPtr == 0 || !Instance.IsRegionMapped(CountPtr, 4))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(uint.MaxValue);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Count = (uint)Win32kRawInput.RegistrationCount(Instance);

            if (DevicesPtr == 0)
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

            if (Count != 0 && !Instance.IsRegionMapped(DevicesPtr, Count * EntrySize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(uint.MaxValue);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (uint Index = 0; Index < Count; Index++)
            {
                if (!Win32kRawInput.TryGetRegistration(Instance, (int)Index, out ushort UsagePage, out ushort Usage, out uint Flags, out ulong Target))
                    break;

                ulong Entry = DevicesPtr + Index * EntrySize;
                Instance._emulator.WriteMemory(Entry, UsagePage | ((uint)Usage << 16), 4);
                Instance._emulator.WriteMemory(Entry + 4, Flags, 4);
                Instance._emulator.WriteMemory(Entry + 8, Target, Instance.IsX86Guest ? 4u : 8u);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Count);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
