namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIEnumAdapters2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Win32kDxgk.EnumerateToArray(Instance, OffsetNumAdapters: 0);
        }
    }
}
