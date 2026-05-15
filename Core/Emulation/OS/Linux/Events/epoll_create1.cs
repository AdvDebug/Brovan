namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal sealed class Epoll_create1 : ILinuxSyscall
    {
        private const int ValidFlags = LinuxEventHelpers.O_CLOEXEC;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int Flags = unchecked((int)Context.Arg0);
            if ((Flags & ~ValidFlags) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            EpollObject Object = new EpollObject();
            ulong DescriptorLimit = SocketHelpers.GetDescriptorLimit(Helper);
            if (!Helper.DescriptorTable.TryAddHandle(Object, (Flags & LinuxEventHelpers.O_CLOEXEC) != 0, DescriptorLimit, out ulong Descriptor))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                return;
            }

            Helper.SetReturnValue(Instance, Context, Descriptor);
        }
    }
}
