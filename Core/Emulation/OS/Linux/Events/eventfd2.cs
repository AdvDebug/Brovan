namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal sealed class Eventfd2 : ILinuxSyscall
    {
        private const int EFD_SEMAPHORE = 1;
        private const int ValidFlags = EFD_SEMAPHORE | LinuxEventHelpers.O_CLOEXEC | LinuxEventHelpers.O_NONBLOCK;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong InitialValue = unchecked((uint)Context.Arg0);
            int Flags = unchecked((int)Context.Arg1);

            if ((Flags & ~ValidFlags) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            bool NonBlocking = (Flags & LinuxEventHelpers.O_NONBLOCK) != 0;
            bool CloseOnExec = (Flags & LinuxEventHelpers.O_CLOEXEC) != 0;
            bool Semaphore = (Flags & EFD_SEMAPHORE) != 0;
            int StatusFlags = SocketHelpers.O_RDWR | (NonBlocking ? LinuxEventHelpers.O_NONBLOCK : 0);
            EventfdObject Object = new EventfdObject(InitialValue, Semaphore, NonBlocking, StatusFlags);

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
