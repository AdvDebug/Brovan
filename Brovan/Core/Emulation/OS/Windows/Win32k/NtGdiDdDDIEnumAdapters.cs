namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIEnumAdapters : IWinSyscall
    {
        // D3DKMT_ENUMADAPTERS carries its adapters inline, unlike the pointer the later versions take.
        private const int OffsetAdapters = 4;
        private const uint InlineAdapters = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            if (ArgumentsPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Win32kDxgk.Enumerate(Instance, ArgumentsPtr, ArgumentsPtr + OffsetAdapters, InlineAdapters);
        }
    }
}
