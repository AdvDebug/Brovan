using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRegisterRawInputDevices : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DevicesPtr = Instance.WinHelper.GetArg(0);
            uint DeviceCount = (uint)Instance.WinHelper.GetArg(1);
            uint EntrySizeArg = (uint)Instance.WinHelper.GetArg(2);

            uint EntrySize = Instance.IsX86Guest ? 12u : 16u;

            if (EntrySizeArg != EntrySize)
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (DeviceCount == 0)
            {
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (DevicesPtr == 0 || !Instance.IsRegionMapped(DevicesPtr, DeviceCount * EntrySize))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            for (uint Index = 0; Index < DeviceCount; Index++)
            {
                ulong Entry = DevicesPtr + Index * EntrySize;
                uint Usages = Instance.ReadMemoryUInt(Entry);
                ushort UsagePage = (ushort)Usages;
                ushort Usage = (ushort)(Usages >> 16);
                uint Flags = Instance.ReadMemoryUInt(Entry + 4);
                ulong Target = Instance.IsX86Guest ? Instance.ReadMemoryUInt(Entry + 8) : Instance.ReadMemoryULong(Entry + 8);

                if (UsagePage == 0 && Usage != 0)
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                // RIDEV_REMOVE tears a registration down, so a window to deliver to is a contradiction.
                if ((Flags & Win32kRawInput.RIDEV_REMOVE) != 0 && Target != 0)
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                uint Selector = Flags & Win32kRawInput.RIDEV_NOLEGACY;
                if (Selector == Win32kRawInput.RIDEV_PAGEONLY && Usage != 0)
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                if ((Flags & (Win32kRawInput.RIDEV_INPUTSINK | Win32kRawInput.RIDEV_EXINPUTSINK)) != 0 && Target == 0)
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                if (Target != 0 && Instance.WinHelper.GetWindow(Target) == null)
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

                Win32kRawInput.Register(Instance, UsagePage, Usage, Flags, Target);

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtUserRegisterRawInputDevices: usage {UsagePage}/{Usage}, flags 0x{Flags:X}, target 0x{Target:X}.", LogFlags.Syscall);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Fail(BinaryEmulator Instance, uint Error)
        {
            Instance.SetLastWinError(Error);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
