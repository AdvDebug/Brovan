using Brovan;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Newfstatat : ILinuxSyscall
    {
        private const int AT_FDCWD = -100;
        private const int AT_SYMLINK_NOFOLLOW = 0x100;
        private const int AT_NO_AUTOMOUNT = 0x800;
        private const int AT_EMPTY_PATH = 0x1000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int DirFd = unchecked((int)Context.Arg0);
            ulong PathPointer = Context.Arg1;
            ulong StatBuffer = Context.Arg2;
            int Flags = unchecked((int)Context.Arg3);
            LinuxStatVariant Variant = Context.Abi == SyscallAbi.X86 ? LinuxStatVariant.Compat64 : LinuxStatVariant.Native;

            int UnsupportedFlags = Flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH);
            if (UnsupportedFlags != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            bool FollowSymlink = (Flags & AT_SYMLINK_NOFOLLOW) == 0;
            bool EmptyPath = false;
            string PathValue = string.Empty;

            if (PathPointer == 0)
            {
                if ((Flags & AT_EMPTY_PATH) == 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                EmptyPath = true;
            }
            else if (!Open.TryReadPath(Instance, PathPointer, out PathValue))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }
            else
            {
                EmptyPath = string.IsNullOrEmpty(PathValue);
            }

            if (EmptyPath)
            {
                if ((Flags & AT_EMPTY_PATH) == 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                    return;
                }

                LinuxErrno EmptyPathError = HandleEmptyPath(Instance, Helper, Context, DirFd, StatBuffer, Variant);
                Helper.SetReturnValue(Instance, Context, EmptyPathError == LinuxErrno.ESUCCESS ? 0L : -(long)EmptyPathError);
                return;
            }

            string ResolvedPath = Openat.ResolveGuestPath(Helper, DirFd, PathValue, out LinuxErrno ResolveError);
            if (ResolvedPath == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)ResolveError);
                return;
            }

            LinuxErrno Error = LinuxStatHelper.WriteResolvedPathStat(Instance, Helper, ResolvedPath, StatBuffer, Variant, FollowSymlink);
            Helper.SetReturnValue(Instance, Context, Error == LinuxErrno.ESUCCESS ? 0L : -(long)Error);
        }

        private static LinuxErrno HandleEmptyPath(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, int DirFd, ulong StatBuffer, LinuxStatVariant Variant)
        {
            if (DirFd == AT_FDCWD)
            {
                string CurrentDirectory = Open.NormalizeLinuxPath(GeneralHelper.IO.LinuxCurrentDirectory);
                if (string.IsNullOrEmpty(CurrentDirectory))
                    CurrentDirectory = "/";

                return LinuxStatHelper.WriteResolvedPathStat(Instance, Helper, CurrentDirectory, StatBuffer, Variant, true);
            }

            if (DirFd < 0)
                return LinuxErrno.EBADF;

            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry((ulong)DirFd);
            if (Entry == null)
                return LinuxErrno.EBADF;

            if (Entry.Object is not FileObject FileDesc)
                return LinuxErrno.EBADF;

            return LinuxStatHelper.WriteStat(Instance, Helper, Context, FileDesc, StatBuffer, Variant);
        }
    }
}
