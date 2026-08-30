namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIEnumAdapters : IWinSyscall
    {
        // D3DKMT_ENUMADAPTERS carries its adapters inline, unlike the pointer the later versions take.
        private const int OffsetAdapters = 4;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, OffsetAdapters + Win32kDxgk.AdapterInfoSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Info = Instance.WinHelper.Shared.GetSpan(Win32kDxgk.AdapterInfoSize);
            Win32kDxgk.WriteAdapterInfo(Info);

            if (!Instance.WriteMemory(ArgumentsPtr + OffsetAdapters, Info.Slice(0, Win32kDxgk.AdapterInfoSize)))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance._emulator.WriteMemory(ArgumentsPtr, 1u, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
