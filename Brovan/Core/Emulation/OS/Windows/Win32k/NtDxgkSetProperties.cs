namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDxgkSetProperties : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryReadProperties(Instance, Instance.WinHelper.GetArg(0), Set: true, out uint Type, out ulong DataPtr))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Type != Win32kDxgk.PropertyDefaultHighPerformanceAdapter)
                return Instance.WinUnimplemented;

            Span<byte> Data = stackalloc byte[DxgkProcess.PreferredAdapterSize];
            if (!Instance.ReadMemory(DataPtr, Data))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (Process.DefaultHighPerformanceAdapterSet)
                return NTSTATUS.STATUS_ALREADY_INITIALIZED;

            Data.CopyTo(Process.DefaultHighPerformanceAdapter);
            Process.DefaultHighPerformanceAdapterSet = true;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
