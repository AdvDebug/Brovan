namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDxgkIsFeatureEnabled : IWinSyscall
    {
        private const int IsFeatureEnabledSize = 12;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // The caller clears the result fields first, so "not enabled" means writing nothing.
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, IsFeatureEnabledSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
