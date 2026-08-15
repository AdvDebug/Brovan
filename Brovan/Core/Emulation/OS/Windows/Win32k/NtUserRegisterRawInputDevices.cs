using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRegisterRawInputDevices : IWinSyscall
    {
        private const uint RIDEV_REMOVE = 0x00000001;
        private const uint RIDEV_EXCLUDE = 0x00000010;
        private const uint RIDEV_PAGEONLY = 0x00000020;
        private const uint RIDEV_NOLEGACY = 0x00000030;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DevicesPtr = Instance.WinHelper.GetArg(0);
            uint DeviceCount = (uint)Instance.WinHelper.GetArg(1);
            uint EntrySizeArg = (uint)Instance.WinHelper.GetArg(2);

            uint EntrySize = Instance.IsX86Guest ? 12u : 16u;

            if (EntrySizeArg != EntrySize)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (DeviceCount == 0)
            {
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (DevicesPtr == 0 || !Instance.IsRegionMapped(DevicesPtr, DeviceCount * EntrySize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (uint Index = 0; Index < DeviceCount; Index++)
            {
                ulong Entry = DevicesPtr + Index * EntrySize;
                ushort UsagePage = (ushort)Instance.ReadMemoryUInt(Entry);
                ushort Usage = (ushort)(Instance.ReadMemoryUInt(Entry) >> 16);
                uint Flags = Instance.ReadMemoryUInt(Entry + 4);
                ulong Target = Instance.IsX86Guest ? Instance.ReadMemoryUInt(Entry + 8) : Instance.ReadMemoryULong(Entry + 8);

                if (UsagePage == 0 && Usage != 0)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                // RIDEV_REMOVE tears a registration down, so a window to deliver to is a contradiction.
                if ((Flags & RIDEV_REMOVE) != 0 && Target != 0)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if ((Flags & RIDEV_EXCLUDE) != 0 && (Flags & RIDEV_PAGEONLY) != 0)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (Target != 0 && Instance.WinHelper.GetWindow(Target) == null)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtUserRegisterRawInputDevices: usage {UsagePage}/{Usage}, flags 0x{Flags:X}, target 0x{Target:X}.", LogFlags.Syscall);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
