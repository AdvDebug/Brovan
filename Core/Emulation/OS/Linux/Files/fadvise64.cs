namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Fadvise64 : ILinuxSyscall
    {
        private enum FadviseAdvice
        {
            POSIX_FADV_NORMAL = 0,
            POSIX_FADV_RANDOM = 1,
            POSIX_FADV_SEQUENTIAL = 2,
            POSIX_FADV_WILLNEED = 3,
            POSIX_FADV_DONTNEED = 4,
            POSIX_FADV_NOREUSE = 5,
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            long offset;
            long length;
            int advice;

            if (Context.Abi == SyscallAbi.X86)
            {
                offset = unchecked((long)(Context.Arg1 | (Context.Arg2 << 32)));
                length = unchecked((int)Context.Arg3);
                advice = unchecked((int)Context.Arg4);
            }
            else
            {
                offset = unchecked((long)Context.Arg1);
                length = unchecked((long)Context.Arg2);
                advice = unchecked((int)Context.Arg3);
            }

            if (!Enum.IsDefined(typeof(FadviseAdvice), advice))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (offset < 0 || length < 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null || Entry.Object is not FileObject)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}
