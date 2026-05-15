namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Socket : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int Domain = unchecked((int)Context.Arg0);
            int Type = unchecked((int)Context.Arg1);
            int Protocol = unchecked((int)Context.Arg2);

            if (!SocketHelpers.TryCreateSocket(Domain, Type, Protocol, out SocketObject SocketObject, out bool CloseOnExec, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            ulong DescriptorLimit = SocketHelpers.GetDescriptorLimit(Helper);
            if (!Helper.DescriptorTable.TryAddHandle(SocketObject, CloseOnExec, DescriptorLimit, out ulong Descriptor))
            {
                SocketObject.Dispose();
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                return;
            }

            Helper.SetReturnValue(Instance, Context, Descriptor);
        }
    }
}
