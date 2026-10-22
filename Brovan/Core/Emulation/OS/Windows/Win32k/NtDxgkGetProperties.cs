namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDxgkGetProperties : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryReadProperties(Instance, Instance.WinHelper.GetArg(0), Set: false, out uint Type, out ulong DataPtr))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Type != Win32kDxgk.PropertyDefaultHighPerformanceAdapter)
                return Instance.WinUnimplemented;

            Span<byte> Data = stackalloc byte[DxgkProcess.PreferredAdapterSize];
            if (!Instance.ReadMemory(DataPtr, Data))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance.WriteMemory(DataPtr, Instance.WinHelper.DxgkProcess.DefaultHighPerformanceAdapter)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
