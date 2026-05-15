using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Stat : ILinuxSyscall
    {
        private readonly bool _useCompat64;

        public Stat(bool UseCompat64 = false)
        {
            _useCompat64 = UseCompat64;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong path = Context.Arg0;
            ulong statbuf = Context.Arg1;

            if (!_useCompat64 && Context.Abi == SyscallAbi.X86)
            {
                LinuxErrno Error32 = WriteStat32(Instance, Helper, path, statbuf, false);
                Helper.SetReturnValue(Instance, Context, Error32 == LinuxErrno.ESUCCESS ? 0L : -(long)Error32);
                return;
            }

            LinuxErrno Error = LinuxStatHelper.WritePathStat(Instance, Helper, Context, path, statbuf, _useCompat64 ? LinuxStatVariant.Compat64 : LinuxStatVariant.Native, true);
            Helper.SetReturnValue(Instance, Context, Error == LinuxErrno.ESUCCESS ? 0L : -(long)Error);
        }

        internal static LinuxErrno WriteStat32(BinaryEmulator Instance, LinuxSyscallsHelper Helper, ulong PathPointer, ulong StatBuffer, bool NoFollowLink)
        {
            if (!Open.TryReadPath(Instance, PathPointer, out string PathValue))
                return LinuxErrno.EFAULT;

            string NormalizedPath = Open.NormalizeLinuxPath(PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return LinuxErrno.ENOENT;

            if (Helper.SpecialPathsHandler.TryCreateSpecialFileObject(Helper, NormalizedPath, out FileObject SpecialFile))
            {
                LinuxErrno SpecialError = LinuxStatHelper.TryCreateStat(Instance, Helper, SpecialFile, NoFollowLink, LinuxStatVariant.Native, out object SpecialStatObject);
                if (SpecialError != LinuxErrno.ESUCCESS)
                    return SpecialError;

                LinuxStat64 SpecialSource = (LinuxStat64)SpecialStatObject;
                LinuxStatData SpecialData = new LinuxStatData
                {
                    Device = SpecialSource.st_dev,
                    Inode = SpecialSource.st_ino,
                    NLink = SpecialSource.st_nlink,
                    Mode = SpecialSource.st_mode,
                    Uid = SpecialSource.st_uid,
                    Gid = SpecialSource.st_gid,
                    RDev = SpecialSource.st_rdev,
                    Size = SpecialSource.st_size,
                    BlockSize = SpecialSource.st_blksize,
                    Blocks = SpecialSource.st_blocks,
                    AccessTime = SpecialSource.st_atim,
                    ModifyTime = SpecialSource.st_mtim,
                    ChangeTime = SpecialSource.st_ctim
                };

                LinuxStat32 SpecialStat32 = LinuxStatHelper.CreateStat32(SpecialData);
                if (!StructSerializer.WriteStruct(Instance, StatBuffer, SpecialStat32).Success)
                    return LinuxErrno.EFAULT;

                return LinuxErrno.ESUCCESS;
            }

            string HostPath;
            if (!Helper.SpecialPathsHandler.TryResolveHostBackedPath(Helper, NormalizedPath, out HostPath))
                HostPath = Helper.ResolveHostPath(NormalizedPath);

            if (string.IsNullOrEmpty(HostPath))
                return LinuxErrno.ENOENT;

            FileObject FileDesc = new FileObject
            {
                Path = NormalizedPath,
                HostPath = HostPath
            };

            LinuxErrno Error = LinuxStatHelper.TryCreateStat(Instance, Helper, FileDesc, NoFollowLink, LinuxStatVariant.Native, out object StatObject);
            if (Error != LinuxErrno.ESUCCESS)
                return Error;

            LinuxStat64 Source = (LinuxStat64)StatObject;
            LinuxStatData Data = new LinuxStatData
            {
                Device = Source.st_dev,
                Inode = Source.st_ino,
                NLink = Source.st_nlink,
                Mode = Source.st_mode,
                Uid = Source.st_uid,
                Gid = Source.st_gid,
                RDev = Source.st_rdev,
                Size = Source.st_size,
                BlockSize = Source.st_blksize,
                Blocks = Source.st_blocks,
                AccessTime = Source.st_atim,
                ModifyTime = Source.st_mtim,
                ChangeTime = Source.st_ctim
            };

            LinuxStat32 Stat32 = LinuxStatHelper.CreateStat32(Data);
            if (!StructSerializer.WriteStruct(Instance, StatBuffer, Stat32).Success)
                return LinuxErrno.EFAULT;

            return LinuxErrno.ESUCCESS;
        }
    }
}
