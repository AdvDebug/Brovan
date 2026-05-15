namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiInit2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return new NtGdiInit().Handle(Instance);
        }
    }
}