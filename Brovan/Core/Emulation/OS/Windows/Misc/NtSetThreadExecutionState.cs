namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetThreadExecutionState : IWinSyscall
    {
        private const uint EsContinuous = 0x80000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PreviousStatePtr = Instance.WinHelper.GetArg(1);

            if (PreviousStatePtr == 0 || !Instance.IsRegionMapped(PreviousStatePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(PreviousStatePtr, EsContinuous, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
