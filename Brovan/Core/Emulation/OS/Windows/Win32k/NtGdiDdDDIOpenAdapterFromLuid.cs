namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIOpenAdapterFromLuid : IWinSyscall
    {
        private const int OpenAdapterFromLuidSize = 12;
        private const int OffsetHandle = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            Span<byte> Arguments = stackalloc byte[OpenAdapterFromLuidSize];
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkAdapter Adapter = Win32kDxgk.FindByLuid(Arguments);
            if (Adapter == null)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryAdd(Adapter, out uint Handle))
                return NTSTATUS.STATUS_NO_MEMORY;

            if (Instance.WinHelper.WriteUInt32(ArgumentsPtr + OffsetHandle, Handle))
                return NTSTATUS.STATUS_SUCCESS;

            Process.TryRemove<DxgkAdapter>(Handle);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
