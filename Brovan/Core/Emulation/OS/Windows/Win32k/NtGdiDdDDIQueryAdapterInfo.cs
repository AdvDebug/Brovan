namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIQueryAdapterInfo : IWinSyscall
    {
        private const int QueryAdapterInfoSize = 24;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, QueryAdapterInfoSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Win32kDxgk.IsAdapter(Instance.ReadMemoryUInt(ArgumentsPtr)))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT rejects a query type the driver does not answer, and Brovan answers none of them: the
            // adapter is synthetic and carries no kernel driver private data.
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
