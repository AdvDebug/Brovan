namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Mprotect : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong addr = Context.Arg0;
            ulong len = Context.Arg1;
            uint prot = (uint)Context.Arg2;

            if (len == 0)
            {
                Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                return;
            }

            if (len > ulong.MaxValue - 0xFFFUL || addr > ulong.MaxValue - len)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong AlignedSize = Instance.AlignToPageSize(len);

            if (!Instance.IsAlignedToPageSize(addr))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsMemoryRangeMapped(addr, AlignedSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                return;
            }

            if (!Instance._emulator.SetMemoryProtection(addr, AlignedSize, Helper.TranslateLinuxMemToNative(prot)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}
