using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Statfs : ILinuxSyscall
    {
        // EXT4 superblock magic.
        private const long EXT4_MAGIC = 0xEF53;

        // 4 KiB blocks — standard ext4 default.
        private const long BLOCK_SIZE = 4096;

        private const long TOTAL_BLOCKS = 0x1000000L;
        private const long FREE_BLOCKS = 0x0800000L;
        private const long AVAIL_BLOCKS = 0x0800000L;
        private const long TOTAL_INODES = 0x0400000L;
        private const long FREE_INODES = 0x0200000L;
        // Maximum filename length on ext4.
        private const long NAME_MAX = 255;
        // Fragment size equals block size on ext4.
        private const long FRAG_SIZE = BLOCK_SIZE;
        // ST_NOSUID flag.
        private const long FLAGS = 2L;

        private const int SIZE_64 = 120;
        private const int SIZE_32 = 64;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong path = Context.Arg0;
            ulong buf = Context.Arg1;

            if (path == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!Open.TryReadPath(Instance, path, out string PathValue))
            {
                Helper.SetReturnValue(Instance, Context, Instance.IsRegionMapped(path, 1) ? -(long)LinuxErrno.ENOENT : -(long)LinuxErrno.EFAULT);
                return;
            }

            if (string.IsNullOrEmpty(PathValue))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            if (Context.Abi == SyscallAbi.X64)
                WriteStatfs64(Instance, Helper, Context, buf);
            else
                WriteStatfs32(Instance, Helper, Context, buf);
        }

        private static void WriteStatfs64(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong bufPtr)
        {
            if (bufPtr == 0 || !Instance.IsRegionMapped(bufPtr, SIZE_64))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> buf = stackalloc byte[SIZE_64];
            buf.Clear();

            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(0, 8), EXT4_MAGIC); // f_type
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(8, 8), BLOCK_SIZE); // f_bsize
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(16, 8), TOTAL_BLOCKS); // f_blocks
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(24, 8), FREE_BLOCKS); // f_bfree
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(32, 8), AVAIL_BLOCKS); // f_bavail
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(40, 8), TOTAL_INODES); // f_files
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(48, 8), FREE_INODES); // f_ffree
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(64, 8), NAME_MAX); // f_namelen
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(72, 8), FRAG_SIZE); // f_frsize
            BinaryPrimitives.WriteInt64LittleEndian(buf.Slice(80, 8), FLAGS); // f_flags

            if (!Instance.WriteMemory(bufPtr, buf))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static void WriteStatfs32(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong bufPtr)
        {
            if (bufPtr == 0 || !Instance.IsRegionMapped(bufPtr, SIZE_32))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> buf = stackalloc byte[SIZE_32];
            buf.Clear();

            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(0, 4), (int)EXT4_MAGIC); // f_type
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(4, 4), (int)BLOCK_SIZE); // f_bsize
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(8, 4), (int)TOTAL_BLOCKS); // f_blocks
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(12, 4), (int)FREE_BLOCKS); // f_bfree
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(16, 4), (int)AVAIL_BLOCKS); // f_bavail
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(20, 4), (int)TOTAL_INODES); // f_files
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(24, 4), (int)FREE_INODES); // f_ffree
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(36, 4), (int)NAME_MAX); // f_namelen
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(40, 4), (int)FRAG_SIZE); // f_frsize
            BinaryPrimitives.WriteInt32LittleEndian(buf.Slice(44, 4), (int)FLAGS); // f_flags

            if (!Instance.WriteMemory(bufPtr, buf))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }
    }
}