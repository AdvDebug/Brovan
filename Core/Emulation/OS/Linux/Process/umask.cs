namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Umask : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            uint OldMask = Helper.Credentials.Umask;
            Helper.Credentials.Umask = (uint)Context.Arg0 & 0x1FF;
            Helper.SetReturnValue(Instance, Context, OldMask);
        }
    }
}
