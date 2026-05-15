namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal sealed class Timerfd_create : ILinuxSyscall
    {
        private const int ValidFlags = LinuxEventHelpers.O_CLOEXEC | LinuxEventHelpers.O_NONBLOCK;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int clockid = unchecked((int)Context.Arg0);
            int flags = unchecked((int)Context.Arg1);

            if (!LinuxEventHelpers.IsValidClockId(clockid))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((flags & ~ValidFlags) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            bool NonBlocking = (flags & LinuxEventHelpers.O_NONBLOCK) != 0;
            bool CloseOnExec = (flags & LinuxEventHelpers.O_CLOEXEC) != 0;
            int StatusFlags = SocketHelpers.O_RDWR | (NonBlocking ? LinuxEventHelpers.O_NONBLOCK : 0);
            TimerfdObject Object = new TimerfdObject(clockid, NonBlocking, StatusFlags);

            ulong DescriptorLimit = SocketHelpers.GetDescriptorLimit(Helper);
            if (!Helper.DescriptorTable.TryAddHandle(Object, CloseOnExec, DescriptorLimit, out ulong Descriptor))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                return;
            }

            Helper.SetReturnValue(Instance, Context, Descriptor);
        }
    }
}
