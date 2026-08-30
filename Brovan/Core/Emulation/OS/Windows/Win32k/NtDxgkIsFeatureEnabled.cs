namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDxgkIsFeatureEnabled : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ResultPtr = Instance.WinHelper.GetArg(1);

            // Every optional kernel graphics feature is off: Brovan implements none of them.
            if (ResultPtr != 0 && Instance.IsRegionMapped(ResultPtr, 4))
                Instance._emulator.WriteMemory(ResultPtr, 0u, 4);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
