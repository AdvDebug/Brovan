namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Getppid : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            Helper.SetReturnValue(Instance, Context, Helper.ParentPid);
        }
    }
}