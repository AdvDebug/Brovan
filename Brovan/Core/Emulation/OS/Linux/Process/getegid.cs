namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Getegid : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            Helper.SetReturnValue(Instance, Helper.Credentials.EffectiveGroupId);
        }
    }
}
