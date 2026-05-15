using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Mount : ILinuxSyscall
    {
        private const ulong MS_RDONLY = 0x1;
        private const ulong MS_REMOUNT = 0x20;
        private const ulong MS_BIND = 0x1000;
        private const ulong MS_MOVE = 0x2000;
        private const ulong MS_REC = 0x4000;
        private const ulong MS_SILENT = 0x8000;
        private const ulong MS_UNBINDABLE = 0x20000;
        private const ulong MS_PRIVATE = 0x40000;
        private const ulong MS_SLAVE = 0x80000;
        private const ulong MS_SHARED = 0x100000;
        private const ulong PropagationMask = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

        private static readonly HashSet<string> SupportedPseudoFileSystems = new(StringComparer.Ordinal)
        {
            "proc",
            "sysfs",
            "tmpfs",
            "devtmpfs",
            "devpts",
            "mqueue",
            "cgroup",
            "cgroup2",
            "ramfs",
            "configfs",
            "securityfs",
            "debugfs",
            "tracefs",
            "fusectl",
            "bpf",
            "hugetlbfs"
        };

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong SourceAddress = Context.Arg0;
            ulong TargetAddress = Context.Arg1;
            ulong FileSystemTypeAddress = Context.Arg2;
            ulong MountFlags = Context.Arg3;

            if (!Open.TryReadPath(Instance, TargetAddress, out string TargetPath))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            string SourcePath = null;
            if (SourceAddress != 0)
            {
                if (!Open.TryReadPath(Instance, SourceAddress, out SourcePath))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            string FileSystemType = null;
            if (FileSystemTypeAddress != 0)
            {
                if (!Open.TryReadPath(Instance, FileSystemTypeAddress, out FileSystemType))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            string NormalizedTarget = Helper.NormalizePath(TargetPath);
            if (string.IsNullOrEmpty(NormalizedTarget))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            int PropagationCount = 0;
            if ((MountFlags & MS_SHARED) != 0)
                PropagationCount++;
            if ((MountFlags & MS_PRIVATE) != 0)
                PropagationCount++;
            if ((MountFlags & MS_SLAVE) != 0)
                PropagationCount++;
            if ((MountFlags & MS_UNBINDABLE) != 0)
                PropagationCount++;

            if (PropagationCount > 1)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((MountFlags & PropagationMask) != 0 && (MountFlags & ~(PropagationMask | MS_REC | MS_SILENT)) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((MountFlags & MS_MOVE) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((MountFlags & MS_REMOUNT) != 0)
            {
                if (!Helper.TryGetMountForPath(NormalizedTarget, out LinuxMountEntry ExistingMount) || ExistingMount.GuestPath != NormalizedTarget)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                Helper.SetMount(ExistingMount.GuestPath, ExistingMount.HostPath, ExistingMount.IsDirectory, (MountFlags & MS_RDONLY) != 0, ExistingMount.FileSystemType);
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if ((MountFlags & MS_BIND) != 0)
            {
                if (string.IsNullOrWhiteSpace(SourcePath))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                string NormalizedSource = Helper.NormalizePath(SourcePath);
                if (string.IsNullOrEmpty(NormalizedSource))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                    return;
                }

                string SourceHostPath = Helper.ResolveHostPath(NormalizedSource);
                string TargetHostPath = Helper.ResolveHostPath(NormalizedTarget);
                if (string.IsNullOrEmpty(SourceHostPath) || string.IsNullOrEmpty(TargetHostPath))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                    return;
                }

                bool SourceIsFile = File.Exists(SourceHostPath);
                bool SourceIsDirectory = Directory.Exists(SourceHostPath);
                bool TargetIsFile = File.Exists(TargetHostPath);
                bool TargetIsDirectory = Directory.Exists(TargetHostPath);

                if ((!SourceIsFile && !SourceIsDirectory) || (!TargetIsFile && !TargetIsDirectory))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                    return;
                }

                if (SourceIsDirectory)
                {
                    if (!TargetIsDirectory)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTDIR);
                        return;
                    }
                }
                else
                {
                    if (!TargetIsFile)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTDIR);
                        return;
                    }
                }

                Helper.SetMount(NormalizedTarget, SourceHostPath, SourceIsDirectory, (MountFlags & MS_RDONLY) != 0, "bind");
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if ((MountFlags & PropagationMask) != 0)
            {
                if (!Helper.TryGetMountForPath(NormalizedTarget, out LinuxMountEntry ExistingMount) || ExistingMount.GuestPath != NormalizedTarget)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (string.IsNullOrWhiteSpace(FileSystemType) || !SupportedPseudoFileSystems.Contains(FileSystemType))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENODEV);
                return;
            }

            string PseudoTargetHostPath = Helper.ResolveHostPath(NormalizedTarget);
            if (string.IsNullOrEmpty(PseudoTargetHostPath))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            if (!Directory.Exists(PseudoTargetHostPath))
            {
                if (File.Exists(PseudoTargetHostPath))
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTDIR);
                else
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            Helper.SetMount(NormalizedTarget, PseudoTargetHostPath, true, (MountFlags & MS_RDONLY) != 0, FileSystemType);
            Helper.SetReturnValue(Instance, Context, 0L);
        }
    }
}