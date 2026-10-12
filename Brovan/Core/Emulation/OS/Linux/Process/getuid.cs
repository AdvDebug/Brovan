namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Getuid : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            Helper.SetReturnValue(Instance, Helper.Credentials.RealUserId);
        }
    }
}
