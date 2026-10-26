namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionDestroyChannel : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
            => Instance.WinHelper.Composition.DestroyChannel(Instance, Instance.WinHelper.GetArg32(0));
    }
}
