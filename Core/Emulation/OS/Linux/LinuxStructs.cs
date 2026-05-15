using System;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.Linux.Files;

namespace Brovan.Core.Emulation.OS.Linux
{
    public struct Utsname
    {
        [EmulatedInline(65, Ascii = true)]
        public string sysname;

        [EmulatedInline(65, Ascii = true)]
        public string nodename;

        [EmulatedInline(65, Ascii = true)]
        public string release;

        [EmulatedInline(65, Ascii = true)]
        public string version;

        [EmulatedInline(65, Ascii = true)]
        public string machine;

        [EmulatedInline(65, Ascii = true)]
        public string domainname;
    }


    [StructLayout(LayoutKind.Explicit)]
    public struct LinuxStat32
    {
        [FieldOffset(0)]
        public ushort st_dev;

        [FieldOffset(2)]
        public short pad1;

        [FieldOffset(4)]
        public uint st_ino;

        [FieldOffset(8)]
        public ushort st_mode;

        [FieldOffset(10)]
        public ushort st_nlink;

        [FieldOffset(12)]
        public ushort st_uid;

        [FieldOffset(14)]
        public ushort st_gid;

        [FieldOffset(16)]
        public ushort st_rdev;

        [FieldOffset(18)]
        public short pad2;

        [FieldOffset(20)]
        public uint st_size;

        [FieldOffset(24)]
        public uint st_blksize;

        [FieldOffset(28)]
        public uint st_blocks;

        [FieldOffset(32)]
        public uint st_atime_;

        [FieldOffset(36)]
        public uint st_atime_nsec_;

        [FieldOffset(40)]
        public uint st_mtime_;

        [FieldOffset(44)]
        public uint st_mtime_nsec_;

        [FieldOffset(48)]
        public uint st_ctime_;

        [FieldOffset(52)]
        public uint st_ctime_nsec_;

        [FieldOffset(56)]
        public uint __unused4;

        [FieldOffset(60)]
        public uint __unused5;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct LinuxStatCompat64
    {
        [FieldOffset(0)]
        public ulong st_dev;

        [FieldOffset(8)]
        public uint __pad0;

        [FieldOffset(12)]
        public uint __st_ino;

        [FieldOffset(16)]
        public uint st_mode;

        [FieldOffset(20)]
        public uint st_nlink;

        [FieldOffset(24)]
        public uint st_uid;

        [FieldOffset(28)]
        public uint st_gid;

        [FieldOffset(32)]
        public ulong st_rdev;

        [FieldOffset(40)]
        public uint __pad3;

        [FieldOffset(44)]
        public long st_size;

        [FieldOffset(52)]
        public uint st_blksize;

        [FieldOffset(56)]
        public ulong st_blocks;

        [FieldOffset(64)]
        public uint st_atime_;

        [FieldOffset(68)]
        public uint st_atime_nsec_;

        [FieldOffset(72)]
        public uint st_mtime_;

        [FieldOffset(76)]
        public uint st_mtime_nsec_;

        [FieldOffset(80)]
        public uint st_ctime_;

        [FieldOffset(84)]
        public uint st_ctime_nsec_;

        [FieldOffset(88)]
        public ulong st_ino;
    }


    [StructLayout(LayoutKind.Explicit)]
    public struct LinuxTimespec64
    {
        [FieldOffset(0)]
        public long tv_sec;

        [FieldOffset(8)]
        public long tv_nsec;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct LinuxStat64
    {
        [FieldOffset(0)]
        public ulong st_dev;

        [FieldOffset(8)]
        public ulong st_ino;

        [FieldOffset(16)]
        public ulong st_nlink;

        [FieldOffset(24)]
        public uint st_mode;

        [FieldOffset(28)]
        public uint st_uid;

        [FieldOffset(32)]
        public uint st_gid;

        [FieldOffset(36)]
        public int __pad0;

        [FieldOffset(40)]
        public ulong st_rdev;

        [FieldOffset(48)]
        public long st_size;

        [FieldOffset(56)]
        public long st_blksize;

        [FieldOffset(64)]
        public long st_blocks;

        [FieldOffset(72)]
        public LinuxTimespec64 st_atim;

        [FieldOffset(88)]
        public LinuxTimespec64 st_mtim;

        [FieldOffset(104)]
        public LinuxTimespec64 st_ctim;

        [FieldOffset(120)]
        public long __glibc_reserved0;

        [FieldOffset(128)]
        public long __glibc_reserved1;

        [FieldOffset(136)]
        public long __glibc_reserved2;
    }
    public struct LinuxStatData
    {
        public ulong Device;
        public ulong Inode;
        public ulong NLink;
        public uint Mode;
        public uint Uid;
        public uint Gid;
        public ulong RDev;
        public long Size;
        public long BlockSize;
        public long Blocks;
        public LinuxTimespec64 AccessTime;
        public LinuxTimespec64 ModifyTime;
        public LinuxTimespec64 ChangeTime;
        public LinuxStatFileKind Kind;
    }
}