using System;
using System.Buffers.Binary;
using System.IO;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Lseek : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            long Offset = Context.Abi == SyscallAbi.X86 ? unchecked((int)(uint)Context.Arg1) : unchecked((long)Context.Arg1);
            int Whence = unchecked((int)Context.Arg2);

            LinuxErrno Error = LinuxSeekHelper.TrySeek(Instance, Helper, Descriptor, Offset, Whence, Context.Abi == SyscallAbi.X86, out long Result);
            if (Error != LinuxErrno.ESUCCESS)
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            Helper.SetReturnValue(Instance, Context, Result);
        }
    }

    internal class Llseek : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            ulong OffsetValue = ((Context.Arg1 & 0xffffffffUL) << 32) | (Context.Arg2 & 0xffffffffUL);
            long Offset = unchecked((long)OffsetValue);
            ulong ResultAddress = Context.Arg3;
            int Whence = unchecked((int)Context.Arg4);

            LinuxErrno Error = LinuxSeekHelper.TrySeek(Instance, Helper, Descriptor, Offset, Whence, false, out long Result);
            if (Error != LinuxErrno.ESUCCESS)
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (!Instance.IsRegionMapped(ResultAddress, 8))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> ResultBuffer = stackalloc byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(ResultBuffer, Result);
            if (!Instance.WriteMemory(ResultAddress, ResultBuffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }
    }

    internal static class LinuxSeekHelper
    {
        private const int SEEK_SET = 0;
        private const int SEEK_CUR = 1;
        private const int SEEK_END = 2;
        private const int SEEK_DATA = 3;
        private const int SEEK_HOLE = 4;
        private const int O_PATH = 0x200000;

        public static LinuxErrno TrySeek(BinaryEmulator Instance, LinuxSyscallsHelper Helper, ulong Descriptor, long Offset, int Whence, bool Compat32Result, out long Result)
        {
            Result = 0;

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Descriptor);
            if (Entry == null)
                return LinuxErrno.EBADF;

            if (!IsValidWhence(Whence))
                return LinuxErrno.EINVAL;

            if (Entry.Object is SocketObject)
                return LinuxErrno.ESPIPE;

            if (Entry.Object is not FileObject FileDesc)
                return LinuxErrno.EBADF;

            if ((FileDesc.StatusFlags & O_PATH) != 0)
                return LinuxErrno.EBADF;

            if (IsTerminalPath(FileDesc.Path))
                return LinuxErrno.ESPIPE;

            if (IsZeroOffsetDevice(FileDesc.Path))
            {
                FileDesc.Offset = 0;
                Result = 0;
                return LinuxErrno.ESUCCESS;
            }

            if (FileDesc.IsDirectory)
                return SeekDirectory(FileDesc, Offset, Whence, Compat32Result, out Result);

            if (!TryGetFileSize(Instance, Helper, FileDesc, out long Size, out LinuxErrno Error))
                return Error;

            Error = ComputeOffset(FileDesc.Offset, Size, Offset, Whence, out Result);
            if (Error != LinuxErrno.ESUCCESS)
                return Error;

            if (Compat32Result && Result > int.MaxValue)
                return LinuxErrno.EOVERFLOW;

            FileDesc.Offset = unchecked((ulong)Result);
            return LinuxErrno.ESUCCESS;
        }

        private static LinuxErrno SeekDirectory(FileObject FileDesc, long Offset, int Whence, bool Compat32Result, out long Result)
        {
            Result = 0;

            LinuxErrno Error = Whence switch
            {
                SEEK_SET => ValidateOffset(Offset, out Result),
                SEEK_CUR => TryAddUnsigned(FileDesc.Offset, Offset, out Result),
                _ => LinuxErrno.EINVAL
            };

            if (Error != LinuxErrno.ESUCCESS)
                return Error;

            if (Compat32Result && Result > int.MaxValue)
                return LinuxErrno.EOVERFLOW;

            FileDesc.Offset = unchecked((ulong)Result);
            return LinuxErrno.ESUCCESS;
        }

        private static LinuxErrno ComputeOffset(ulong CurrentOffset, long Size, long Offset, int Whence, out long Result)
        {
            Result = 0;

            return Whence switch
            {
                SEEK_SET => ValidateOffset(Offset, out Result),
                SEEK_CUR => TryAddUnsigned(CurrentOffset, Offset, out Result),
                SEEK_END => TryAdd(Size, Offset, out Result),
                SEEK_DATA => SeekData(Size, Offset, out Result),
                SEEK_HOLE => SeekHole(Size, Offset, out Result),
                _ => LinuxErrno.EINVAL
            };
        }

        private static LinuxErrno SeekData(long Size, long Offset, out long Result)
        {
            Result = 0;
            if (Offset < 0)
                return LinuxErrno.EINVAL;

            if (Offset >= Size)
                return LinuxErrno.ENXIO;

            Result = Offset;
            return LinuxErrno.ESUCCESS;
        }

        private static LinuxErrno SeekHole(long Size, long Offset, out long Result)
        {
            Result = 0;
            if (Offset < 0)
                return LinuxErrno.EINVAL;

            if (Offset > Size)
                return LinuxErrno.ENXIO;

            Result = Size;
            return LinuxErrno.ESUCCESS;
        }

        private static LinuxErrno ValidateOffset(long Offset, out long Result)
        {
            Result = 0;
            if (Offset < 0)
                return LinuxErrno.EINVAL;

            Result = Offset;
            return LinuxErrno.ESUCCESS;
        }

        private static LinuxErrno TryAdd(long BaseOffset, long Offset, out long Result)
        {
            Result = 0;
            try
            {
                Result = checked(BaseOffset + Offset);
            }
            catch (OverflowException)
            {
                return LinuxErrno.EOVERFLOW;
            }

            if (Result < 0)
                return LinuxErrno.EINVAL;

            return LinuxErrno.ESUCCESS;
        }

        private static LinuxErrno TryAddUnsigned(ulong BaseOffset, long Offset, out long Result)
        {
            Result = 0;
            if (BaseOffset > long.MaxValue)
                return LinuxErrno.EOVERFLOW;

            return TryAdd((long)BaseOffset, Offset, out Result);
        }

        private static bool IsValidWhence(int Whence)
        {
            return Whence >= SEEK_SET && Whence <= SEEK_HOLE;
        }

        private static bool TryGetFileSize(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject FileDesc, out long Size, out LinuxErrno Error)
        {
            Size = 0;
            Error = LinuxErrno.ESUCCESS;

            if (FileDesc.IsSpecialPath)
            {
                if (!Helper.SpecialPathsHandler.TryCreateSpecialStatData(Instance, Helper, FileDesc, out LinuxStatData Data))
                {
                    Error = LinuxErrno.ESPIPE;
                    return false;
                }

                if (Data.Kind != LinuxStatFileKind.RegularFile)
                {
                    Error = LinuxErrno.ESPIPE;
                    return false;
                }

                Size = Data.Size;
                return true;
            }

            try
            {
                Size = FileDesc.FileStream != null ? FileDesc.FileStream.Length : new FileInfo(FileDesc.HostPath).Length;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Error = LinuxErrno.EACCES;
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                Error = LinuxErrno.ENOENT;
                return false;
            }
            catch (FileNotFoundException)
            {
                Error = LinuxErrno.ENOENT;
                return false;
            }
            catch (PathTooLongException)
            {
                Error = LinuxErrno.ENAMETOOLONG;
                return false;
            }
            catch (ArgumentException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (NotSupportedException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (IOException)
            {
                Error = LinuxErrno.EIO;
                return false;
            }
        }

        private static bool IsTerminalPath(string PathValue)
        {
            return string.Equals(PathValue, "/dev/stdin", StringComparison.Ordinal)
                || string.Equals(PathValue, "/dev/stdout", StringComparison.Ordinal)
                || string.Equals(PathValue, "/dev/stderr", StringComparison.Ordinal);
        }

        private static bool IsZeroOffsetDevice(string PathValue)
        {
            return string.Equals(PathValue, "/dev/null", StringComparison.Ordinal)
                || string.Equals(PathValue, "/dev/zero", StringComparison.Ordinal)
                || string.Equals(PathValue, "/dev/random", StringComparison.Ordinal)
                || string.Equals(PathValue, "/dev/urandom", StringComparison.Ordinal);
        }
    }
}
