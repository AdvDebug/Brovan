namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICloseAdapter : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, 4))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Win32kDxgk.IsAdapter(Instance.ReadMemoryUInt(ArgumentsPtr))
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
