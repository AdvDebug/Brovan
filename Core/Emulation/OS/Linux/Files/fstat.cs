using System;
using System.IO;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal static class LinuxStatHelper
    {
        private const uint S_IFREG = 0x8000;
        private const uint S_IFDIR = 0x4000;
        private const uint S_IFCHR = 0x2000;
        private const uint S_IFLNK = 0xA000;
        private const uint MODE_REGULAR = 0x1A4;
        private const uint MODE_DIRECTORY = 0x1ED;
        private const uint MODE_CHARACTER = 0x1B6;
        private const uint MODE_SYMLINK = 0x1FF;
        private const long DEFAULT_BLOCK_SIZE = 4096;

        public static LinuxErrno WriteStat(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, FileObject FileDesc, ulong StatBuffer, LinuxStatVariant Variant)
        {
            LinuxErrno Error = TryCreateStat(Instance, Helper, FileDesc, false, Variant, out object StatObject);
            if (Error != LinuxErrno.ESUCCESS)
                return Error;

            return WriteStatObject(Instance, StatBuffer, StatObject);
        }

        public static LinuxErrno WritePathStat(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong PathPointer, ulong StatBuffer, LinuxStatVariant Variant, bool FollowSymlink)
        {
            if (!Open.TryReadPath(Instance, PathPointer, out string PathValue))
                return LinuxErrno.EFAULT;

            string NormalizedPath = Open.NormalizeLinuxPath(PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return LinuxErrno.ENOENT;

            return WriteResolvedPathStat(Instance, Helper, NormalizedPath, StatBuffer, Variant, FollowSymlink);
        }

        internal static LinuxErrno WriteResolvedPathStat(BinaryEmulator Instance, LinuxSyscallsHelper Helper, string NormalizedPath, ulong StatBuffer, LinuxStatVariant Variant, bool FollowSymlink)
        {
            if (string.IsNullOrEmpty(NormalizedPath))
                return LinuxErrno.ENOENT;

            if (Helper.SpecialPathsHandler.TryCreateSpecialFileObject(Helper, NormalizedPath, out FileObject SpecialFile))
            {
                LinuxErrno SpecialError = TryCreateStat(Instance, Helper, SpecialFile, !FollowSymlink, Variant, out object SpecialStat);
                if (SpecialError != LinuxErrno.ESUCCESS)
                    return SpecialError;

                return WriteStatObject(Instance, StatBuffer, SpecialStat);
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

            LinuxErrno Error = TryCreateStat(Instance, Helper, FileDesc, !FollowSymlink, Variant, out object StatObject);
            if (Error != LinuxErrno.ESUCCESS)
                return Error;

            return WriteStatObject(Instance, StatBuffer, StatObject);
        }

        internal static LinuxErrno TryCreateStat(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject FileDesc, bool NoFollowLink, LinuxStatVariant Variant, out object StatObject)
        {
            StatObject = null;
            try
            {
                LinuxStatData Data;
                if (FileDesc.IsSpecialPath)
                {
                    if (!Helper.SpecialPathsHandler.TryCreateSpecialStatData(Instance, Helper, FileDesc, out Data))
                        Data = CreateSpecialData(FileDesc);
                }
                else
                {
                    Data = CreateHostData(FileDesc, NoFollowLink);
                }
                StatObject = Variant switch
                {
                    LinuxStatVariant.Compat64 => CreateCompat64Stat(Data),
                    _ => CreateNativeStat(Data, FileDesc)
                };

                return LinuxErrno.ESUCCESS;
            }
            catch (UnauthorizedAccessException)
            {
                return LinuxErrno.EACCES;
            }
            catch (DirectoryNotFoundException)
            {
                return LinuxErrno.ENOENT;
            }
            catch (FileNotFoundException)
            {
                return LinuxErrno.ENOENT;
            }
            catch (PathTooLongException)
            {
                return LinuxErrno.ENAMETOOLONG;
            }
            catch (ArgumentException)
            {
                return LinuxErrno.EINVAL;
            }
            catch (NotSupportedException)
            {
                return LinuxErrno.EINVAL;
            }
            catch (IOException)
            {
                return LinuxErrno.EIO;
            }
        }

        private static LinuxErrno WriteStatObject(BinaryEmulator Instance, ulong StatBuffer, object StatObject)
        {
            if (StatObject is LinuxStat64 NativeStat)
            {
                if (!StructSerializer.WriteStruct(Instance, StatBuffer, NativeStat).Success)
                    return LinuxErrno.EFAULT;

                return LinuxErrno.ESUCCESS;
            }

            if (StatObject is LinuxStatCompat64 Compat64Stat)
            {
                if (!StructSerializer.WriteStruct(Instance, StatBuffer, Compat64Stat).Success)
                    return LinuxErrno.EFAULT;

                return LinuxErrno.ESUCCESS;
            }

            return LinuxErrno.EINVAL;
        }

        private static LinuxStatData CreateHostData(FileObject FileDesc, bool NoFollowLink)
        {
            FileSystemInfo Info = GetFileSystemInfo(FileDesc.HostPath);
            if (!Info.Exists && string.IsNullOrEmpty(Info.LinkTarget))
                throw new FileNotFoundException(FileDesc.HostPath);

            bool IsDirectory = FileDesc.IsDirectory || Info is DirectoryInfo;
            LinuxStatFileKind Kind = IsDirectory ? LinuxStatFileKind.Directory : LinuxStatFileKind.RegularFile;
            long Size = 0;
            ulong Device = ComputeStableId(Path.GetPathRoot(Info.FullName) ?? string.Empty);
            ulong Inode = ComputeStableId(Info.FullName);
            ulong RDev = 0;
            ulong NLink = IsDirectory ? 2UL : 1UL;
            uint Mode = IsDirectory ? (S_IFDIR | MODE_DIRECTORY) : (S_IFREG | MODE_REGULAR);

            if (NoFollowLink && !string.IsNullOrEmpty(Info.LinkTarget))
            {
                Kind = LinuxStatFileKind.SymbolicLink;
                Mode = S_IFLNK | MODE_SYMLINK;
                Size = Info.LinkTarget.Length;
                NLink = 1;
            }
            else if (IsDirectory)
            {
                Size = DEFAULT_BLOCK_SIZE;
            }
            else if (Info is FileInfo FileInfo)
            {
                Size = FileInfo.Length;
            }
            else
            {
                Size = DEFAULT_BLOCK_SIZE;
            }

            DateTimeOffset AccessTime = new DateTimeOffset(Info.LastAccessTimeUtc, TimeSpan.Zero);
            DateTimeOffset WriteTime = new DateTimeOffset(Info.LastWriteTimeUtc, TimeSpan.Zero);
            DateTimeOffset ChangeTime = new DateTimeOffset(Info.CreationTimeUtc, TimeSpan.Zero);

            return new LinuxStatData
            {
                Device = Device,
                Inode = Inode,
                NLink = NLink,
                Mode = Mode,
                Uid = 0,
                Gid = 0,
                RDev = RDev,
                Size = Size,
                BlockSize = DEFAULT_BLOCK_SIZE,
                Blocks = GetBlockCount(Size),
                AccessTime = ToTimespec64(AccessTime),
                ModifyTime = ToTimespec64(WriteTime),
                ChangeTime = ToTimespec64(ChangeTime),
                Kind = Kind
            };
        }

        private static LinuxStatData CreateSpecialData(FileObject FileDesc)
        {
            ulong StableId = ComputeStableId(FileDesc.Path ?? string.Empty);
            LinuxTimespec64 Now = ToTimespec64(DateTimeOffset.UtcNow);
            return new LinuxStatData
            {
                Device = StableId,
                Inode = StableId,
                NLink = 1,
                Mode = S_IFCHR | MODE_CHARACTER,
                Uid = 0,
                Gid = 0,
                RDev = StableId,
                Size = 0,
                BlockSize = DEFAULT_BLOCK_SIZE,
                Blocks = 0,
                AccessTime = Now,
                ModifyTime = Now,
                ChangeTime = Now,
                Kind = LinuxStatFileKind.CharacterDevice
            };
        }

        private static object CreateNativeStat(LinuxStatData Data, FileObject FileDesc)
        {
            if (FileDesc != null && FileDesc.IsSpecialPath)
            {
                return new LinuxStat64
                {
                    st_dev = Data.Device,
                    st_ino = Data.Inode,
                    st_nlink = Data.NLink,
                    st_mode = Data.Mode,
                    st_uid = Data.Uid,
                    st_gid = Data.Gid,
                    st_rdev = Data.RDev,
                    st_size = Data.Size,
                    st_blksize = Data.BlockSize,
                    st_blocks = Data.Blocks,
                    st_atim = Data.AccessTime,
                    st_mtim = Data.ModifyTime,
                    st_ctim = Data.ChangeTime
                };
            }

            return new LinuxStat64
            {
                st_dev = Data.Device,
                st_ino = Data.Inode,
                st_nlink = Data.NLink,
                st_mode = Data.Mode,
                st_uid = Data.Uid,
                st_gid = Data.Gid,
                st_rdev = Data.RDev,
                st_size = Data.Size,
                st_blksize = Data.BlockSize,
                st_blocks = Data.Blocks,
                st_atim = Data.AccessTime,
                st_mtim = Data.ModifyTime,
                st_ctim = Data.ChangeTime
            };
        }

        private static LinuxStatCompat64 CreateCompat64Stat(LinuxStatData Data)
        {
            return new LinuxStatCompat64
            {
                st_dev = Data.Device,
                __st_ino = (uint)Math.Min(Data.Inode, uint.MaxValue),
                st_mode = Data.Mode,
                st_nlink = (uint)Math.Min(Data.NLink, uint.MaxValue),
                st_uid = Data.Uid,
                st_gid = Data.Gid,
                st_rdev = Data.RDev,
                st_size = Data.Size,
                st_blksize = (uint)Math.Min((ulong)Data.BlockSize, uint.MaxValue),
                st_blocks = (ulong)Math.Max(Data.Blocks, 0),
                st_atime_ = (uint)Math.Clamp(Data.AccessTime.tv_sec, 0, uint.MaxValue),
                st_atime_nsec_ = (uint)Math.Clamp(Data.AccessTime.tv_nsec, 0, uint.MaxValue),
                st_mtime_ = (uint)Math.Clamp(Data.ModifyTime.tv_sec, 0, uint.MaxValue),
                st_mtime_nsec_ = (uint)Math.Clamp(Data.ModifyTime.tv_nsec, 0, uint.MaxValue),
                st_ctime_ = (uint)Math.Clamp(Data.ChangeTime.tv_sec, 0, uint.MaxValue),
                st_ctime_nsec_ = (uint)Math.Clamp(Data.ChangeTime.tv_nsec, 0, uint.MaxValue),
                st_ino = Data.Inode
            };
        }

        public static LinuxStat32 CreateStat32(LinuxStatData Data)
        {
            return new LinuxStat32
            {
                st_dev = (ushort)Math.Min(Data.Device, ushort.MaxValue),
                st_ino = (uint)Math.Min(Data.Inode, uint.MaxValue),
                st_mode = (ushort)Math.Min(Data.Mode, ushort.MaxValue),
                st_nlink = (ushort)Math.Min(Data.NLink, ushort.MaxValue),
                st_uid = (ushort)Math.Min(Data.Uid, ushort.MaxValue),
                st_gid = (ushort)Math.Min(Data.Gid, ushort.MaxValue),
                st_rdev = (ushort)Math.Min(Data.RDev, ushort.MaxValue),
                st_size = Data.Size <= 0 ? 0U : (uint)Math.Min((ulong)Data.Size, uint.MaxValue),
                st_blksize = (uint)Math.Min((ulong)Data.BlockSize, uint.MaxValue),
                st_blocks = Data.Blocks <= 0 ? 0U : (uint)Math.Min((ulong)Data.Blocks, uint.MaxValue),
                st_atime_ = (uint)Math.Clamp(Data.AccessTime.tv_sec, 0, uint.MaxValue),
                st_atime_nsec_ = (uint)Math.Clamp(Data.AccessTime.tv_nsec, 0, uint.MaxValue),
                st_mtime_ = (uint)Math.Clamp(Data.ModifyTime.tv_sec, 0, uint.MaxValue),
                st_mtime_nsec_ = (uint)Math.Clamp(Data.ModifyTime.tv_nsec, 0, uint.MaxValue),
                st_ctime_ = (uint)Math.Clamp(Data.ChangeTime.tv_sec, 0, uint.MaxValue),
                st_ctime_nsec_ = (uint)Math.Clamp(Data.ChangeTime.tv_nsec, 0, uint.MaxValue)
            };
        }

        public static LinuxTimespec64 ToTimespec64(DateTimeOffset Value)
        {
            DateTimeOffset UtcValue = Value.ToUniversalTime();
            long Seconds = UtcValue.ToUnixTimeSeconds();
            long Nanoseconds = (UtcValue.Ticks % TimeSpan.TicksPerSecond) * 100;
            if (Nanoseconds < 0)
                Nanoseconds = 0;

            return new LinuxTimespec64
            {
                tv_sec = Seconds,
                tv_nsec = Nanoseconds
            };
        }

        public static long GetBlockCount(long Size)
        {
            if (Size <= 0)
                return 0;

            return (Size + 511) / 512;
        }

        public static ulong ComputeStableId(string Value)
        {
            const ulong Offset = 14695981039346656037UL;
            const ulong Prime = 1099511628211UL;
            ulong Hash = Offset;
            string Source = Value ?? string.Empty;

            for (int i = 0; i < Source.Length; i++)
            {
                Hash ^= Source[i];
                Hash *= Prime;
            }

            return Hash;
        }

        private static FileSystemInfo GetFileSystemInfo(string HostPath)
        {
            DirectoryInfo Directory = new DirectoryInfo(HostPath);
            Directory.Refresh();
            if (Directory.Exists)
                return Directory;

            FileInfo File = new FileInfo(HostPath);
            File.Refresh();
            if (File.Exists || !string.IsNullOrEmpty(File.LinkTarget))
                return File;

            Directory = new DirectoryInfo(HostPath);
            Directory.Refresh();
            if (!string.IsNullOrEmpty(Directory.LinkTarget))
                return Directory;

            throw new FileNotFoundException(HostPath);
        }
    }

    internal class Fstat : ILinuxSyscall
    {
        private readonly bool _useCompat64;

        public Fstat(bool UseCompat64 = false)
        {
            _useCompat64 = UseCompat64;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong statbuf = Context.Arg1;

            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null || Entry.Object is not FileObject FileDesc)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (!_useCompat64 && Context.Abi == SyscallAbi.X86)
            {
                LinuxErrno Error = WriteStat32(Instance, Helper, FileDesc, statbuf);
                Helper.SetReturnValue(Instance, Context, Error == LinuxErrno.ESUCCESS ? 0L : -(long)Error);
                return;
            }

            LinuxErrno NativeError = LinuxStatHelper.WriteStat(Instance, Helper, Context, FileDesc, statbuf, _useCompat64 ? LinuxStatVariant.Compat64 : LinuxStatVariant.Native);
            Helper.SetReturnValue(Instance, Context, NativeError == LinuxErrno.ESUCCESS ? 0L : -(long)NativeError);
        }

        internal static LinuxErrno WriteStat32(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject FileDesc, ulong StatBuffer)
        {
            LinuxErrno Error = LinuxStatHelper.TryCreateStat(Instance, Helper, FileDesc, false, LinuxStatVariant.Native, out object StatObject);
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
