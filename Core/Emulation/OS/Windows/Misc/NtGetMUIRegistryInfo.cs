using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtGetMUIRegistryInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            uint Flags;
            ulong DataSizePtr;
            ulong DataPtr;

            if (Is64)
            {
                Flags = (uint)Instance.WinHelper.GetArg64(0);
                DataSizePtr = Instance.WinHelper.GetArg64(1);
                DataPtr = Instance.WinHelper.GetArg64(2);
            }
            else
            {
                Flags = Instance.WinHelper.GetArg32(0);
                DataSizePtr = Instance.WinHelper.GetArg32(1);
                DataPtr = Instance.WinHelper.GetArg32(2);
            }

            if (DataSizePtr == 0 || !Instance.IsRegionMapped(DataSizePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint BufferSize = Instance._emulator.ReadMemoryUInt(DataSizePtr);
            if (DataPtr != 0 && BufferSize != 0 && !Instance.IsRegionMapped(DataPtr, BufferSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.TriggerEventMessage($"[+] NtGetMUIRegistryInfo: No kernel MUI registry cache is exposed (Flags=0x{Flags:X}, BufferSize=0x{BufferSize:X}).", LogFlags.Syscall);
            return NTSTATUS.STATUS_NOT_SUPPORTED;
        }
    }
}
