namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64GetCurrentProcessorNumberEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessorNumberPtr = Instance.WinHelper.GetArg(0);

            if (ProcessorNumberPtr == 0 || !Instance.IsRegionMapped(ProcessorNumberPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // PROCESSOR_NUMBER: Group, Number, Reserved.
            Instance._emulator.WriteMemory(ProcessorNumberPtr, (ushort)0, 2);
            Instance._emulator.WriteMemory(ProcessorNumberPtr + 2, (byte)0, 1);
            Instance._emulator.WriteMemory(ProcessorNumberPtr + 3, (byte)0, 1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
