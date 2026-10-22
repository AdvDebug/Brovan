namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDxgkEnumAdapters3 : IWinSyscall
    {
        // D3DKMT_ENUMADAPTERS3 opens with D3DKMT_ENUMADAPTERS_FILTER, a ULONGLONG on both architectures.
        private const int OffsetNumAdapters = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Win32kDxgk.EnumerateToArray(Instance, OffsetNumAdapters);
        }
    }
}
