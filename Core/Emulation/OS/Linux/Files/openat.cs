using System;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Openat : ILinuxSyscall
    {
        private const int AT_FDCWD = -100;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            if (!Open.TryReadPath(Instance, Context.Arg1, out string PathValue))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Instance.TriggerEventMessage($"[openat] Opening file with path {PathValue}", LogFlags.Syscall);

            int DirFd = unchecked((int)Context.Arg0);
            string ResolvedPath = ResolveGuestPath(Helper, DirFd, PathValue, out LinuxErrno Error);
            if (ResolvedPath == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            Open.HandleOpenPath(Instance, Helper, Context, ResolvedPath, unchecked((int)Context.Arg2), unchecked((uint)Context.Arg3), true);
        }

        internal static string ResolveGuestPath(LinuxSyscallsHelper Helper, int DirFd, string PathValue, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;
            if (string.IsNullOrEmpty(PathValue))
            {
                Error = LinuxErrno.ENOENT;
                return null;
            }

            if (PathValue.StartsWith("/", StringComparison.Ordinal) || PathValue.StartsWith("\\", StringComparison.Ordinal))
                return Open.NormalizeLinuxPath(PathValue);

            if (DirFd == AT_FDCWD)
                return Open.NormalizeLinuxPath(PathValue);

            if (DirFd < 0)
            {
                Error = LinuxErrno.EBADF;
                return null;
            }

            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry((ulong)DirFd);
            if (Entry == null)
            {
                Error = LinuxErrno.EBADF;
                return null;
            }

            if (Entry.Object is not FileObject DirectoryObject || !DirectoryObject.IsDirectory)
            {
                Error = LinuxErrno.ENOTDIR;
                return null;
            }

            string BasePath = Open.NormalizeLinuxPath(DirectoryObject.Path);
            if (string.IsNullOrEmpty(BasePath))
                BasePath = "/";

            return Open.NormalizeLinuxPath(PathValue, BasePath);
        }
    }
}
