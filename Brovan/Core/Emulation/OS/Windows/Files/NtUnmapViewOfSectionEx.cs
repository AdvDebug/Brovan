using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtUnmapViewOfSectionEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                ulong BaseAddress = Instance.WinHelper.GetArg(1);
                uint Flags = (uint)Instance.WinHelper.GetArg(2);

                return UnmapView(Instance, ProcessHandle, BaseAddress, Flags, nameof(NtUnmapViewOfSectionEx));
            }
            else
            {
                uint ProcessHandle = Instance.WinHelper.GetArg32(0);
                uint BaseAddress = Instance.WinHelper.GetArg32(1);
                uint Flags = Instance.WinHelper.GetArg32(2);

                return UnmapView(Instance, ProcessHandle, BaseAddress, Flags, nameof(NtUnmapViewOfSectionEx));
            }
        }

        internal static NTSTATUS UnmapView(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddress, uint Flags, string SyscallName)
        {
            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (BaseAddress == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.UnmapViewOfSection(BaseAddress))
                return NTSTATUS.STATUS_INVALID_ADDRESS;

            Instance.WinHelper.LdrTracker?.NotifyImageMapped();

            if (Flags == 0 && string.Equals(SyscallName, nameof(NtUnmapViewOfSection), StringComparison.Ordinal))
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtUnmapViewOfSection: Base=0x{BaseAddress:X}", LogFlags.Syscall);
            else
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] {SyscallName}: Base=0x{BaseAddress:X}, Flags=0x{Flags:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
