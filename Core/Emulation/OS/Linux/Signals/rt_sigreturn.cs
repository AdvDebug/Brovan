namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Rt_sigreturn : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            LinuxSignalHelpers.RestoreSignalContext(Instance, Helper, Context);
        }
    }
}
