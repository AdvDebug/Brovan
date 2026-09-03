using System;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation
{

    internal static class KvmNative
    {

        [DllImport("libc", SetLastError = true)]
        public static extern int open(string pathname, int flags, int mode);

        [DllImport("libc", SetLastError = true)]
        public static extern int close(int fd);

        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr mmap(IntPtr addr, UIntPtr length, int prot, int flags, int fd, long offset);

        [DllImport("libc", SetLastError = true)]
        public static extern int munmap(IntPtr addr, UIntPtr length);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, IntPtr arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref int arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref uint arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref LinuxKvmUserspaceMemoryRegion arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref LinuxKvmRegisters arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref LinuxKvmSpecialRegisters arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref LinuxKvmMsrs arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref LinuxKvmVcpuEvents arg);

        [DllImport("libc", SetLastError = true)]
        public static extern int ioctl(int fd, uint request, ref LinuxKvmDebugRegisters arg);

        [DllImport("libc")]
        public static extern int getpid();

        [DllImport("libc")]
        public static extern int gettid();

        [DllImport("libc", SetLastError = true)]
        public static extern int tgkill(int tgid, int tid, int sig);

        [DllImport("libc")]
        public static extern int __libc_current_sigrtmin();

        [DllImport("libc", SetLastError = true)]
        public static extern int getrlimit(int resource, ref LinuxRlimit rlim);

        [DllImport("libc", SetLastError = true)]
        public static extern int setrlimit(int resource, ref LinuxRlimit rlim);

        public const int RLIMIT_NOFILE = 7;

        public const int O_RDWR = 0x02;
        public const int O_CLOEXEC = 0x080000;

        public const int PROT_READ = 0x1;
        public const int PROT_WRITE = 0x2;
        public const int PROT_EXEC = 0x4;

        public const int MAP_SHARED = 0x01;
        public const int MAP_PRIVATE = 0x02;
        public const int MAP_ANONYMOUS = 0x20;
        public static readonly IntPtr MAP_FAILED = new IntPtr(-1);

        public const int ErrnoEintr = 4;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxRlimit
    {
        public ulong Current;
        public ulong Maximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmUserspaceMemoryRegion
    {
        public uint Slot;
        public uint Flags;
        public ulong GuestPhysAddr;
        public ulong MemorySize;
        public ulong UserspaceAddr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmSegment
    {
        public ulong Base;
        public uint Limit;
        public ushort Selector;
        public byte Type;
        public byte Present;
        public byte Dpl;
        public byte Db;
        public byte S;
        public byte L;
        public byte G;
        public byte Avl;
        public byte Unusable;
        public byte Padding;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmDescriptorTable
    {
        public ulong Base;
        public ushort Limit;
        public ushort Padding0;
        public ushort Padding1;
        public ushort Padding2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct LinuxKvmSpecialRegisters
    {
        public LinuxKvmSegment Cs;
        public LinuxKvmSegment Ds;
        public LinuxKvmSegment Es;
        public LinuxKvmSegment Fs;
        public LinuxKvmSegment Gs;
        public LinuxKvmSegment Ss;
        public LinuxKvmSegment Tr;
        public LinuxKvmSegment Ldt;
        public LinuxKvmDescriptorTable Gdt;
        public LinuxKvmDescriptorTable Idt;
        public ulong Cr0;
        public ulong Cr2;
        public ulong Cr3;
        public ulong Cr4;
        public ulong Cr8;
        public ulong Efer;
        public ulong ApicBase;
        public fixed ulong InterruptBitmap[4];
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmRegisters
    {
        public ulong Rax;
        public ulong Rbx;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rsi;
        public ulong Rdi;
        public ulong Rsp;
        public ulong Rbp;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
        public ulong Rflags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct LinuxKvmFpu
    {
        public fixed byte Fpr[128];
        public ushort Fcw;
        public ushort Fsw;
        public byte Ftwx;
        public byte Pad1;
        public ushort LastOpcode;
        public ulong LastIp;
        public ulong LastDp;
        public fixed byte Xmm[256];
        public uint Mxcsr;
        public uint Pad2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmMsrEntry
    {
        public uint Index;
        public uint _pad0;
        public ulong Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmMsrs
    {
        public uint Count;
        public uint _pad0;
        public LinuxKvmMsrEntry FirstEntry;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct LinuxKvmDebugRegisters
    {
        public fixed ulong Db[4];
        public ulong Dr6;
        public ulong Dr7;
        public ulong Flags;
        public fixed ulong Reserved[9];
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmVcpuEventsException
    {
        public byte Injected;
        public byte Nr;
        public byte HasErrorCode;
        public byte Pending;
        public uint ErrorCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmVcpuEventsInterrupt
    {
        public byte Injected;
        public byte Nr;
        public byte Soft;
        public byte Shadow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmVcpuEventsNmi
    {
        public byte Injected;
        public byte Pending;
        public byte Masked;
        public byte Pad;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmVcpuEventsSmi
    {
        public byte Smm;
        public byte Pending;
        public byte SmmInsideNmi;
        public byte LatchedInit;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmVcpuEventsTripleFault
    {
        public byte Pending;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct LinuxKvmVcpuEvents
    {
        public LinuxKvmVcpuEventsException Exception;
        public LinuxKvmVcpuEventsInterrupt Interrupt;
        public LinuxKvmVcpuEventsNmi Nmi;
        public uint SipiVector;
        public uint Flags;
        public LinuxKvmVcpuEventsSmi Smi;
        public LinuxKvmVcpuEventsTripleFault TripleFault;
        public fixed byte Reserved[26];
        public byte ExceptionHasPayload;
        public ulong ExceptionPayload;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmCpuidEntry2
    {
        public uint Function;
        public uint Index;
        public uint Flags;
        public uint Eax;
        public uint Ebx;
        public uint Ecx;
        public uint Edx;
        public uint Padding0;
        public uint Padding1;
        public uint Padding2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmCpuid2
    {
        public uint Nent;
        public uint _pad0;
        public LinuxKvmCpuidEntry2 FirstEntry;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmMmioExit
    {
        public ulong PhysAddr;
        public ulong Data;
        public uint Len;
        public byte IsWrite;
        public byte Pad0;
        public byte Pad1;
        public byte Pad2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmDebugExitArch
    {
        public uint Exception;
        public uint Pad;
        public ulong Pc;
        public ulong Dr6;
        public ulong Dr7;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmRunExitException
    {
        public uint Exception;
        public uint ErrorCode;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmRunExitFailEntry
    {
        public ulong HardwareEntryFailureReason;
        public uint Cpu;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LinuxKvmRunExitInternalError
    {
        public uint Suberror;
        public uint Ndata;
        public ulong Data0;
        public ulong Data1;
        public ulong Data2;
        public ulong Data3;
        public ulong Data4;
        public ulong Data5;
        public ulong Data6;
        public ulong Data7;
        public ulong Data8;
        public ulong Data9;
        public ulong Data10;
        public ulong Data11;
        public ulong Data12;
        public ulong Data13;
        public ulong Data14;
        public ulong Data15;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    internal unsafe struct LinuxKvmRunExit
    {
        [FieldOffset(0)] public LinuxKvmRunExitException Exception;
        [FieldOffset(0)] public LinuxKvmRunExitFailEntry FailEntry;
        [FieldOffset(0)] public LinuxKvmRunExitInternalError InternalError;
        [FieldOffset(0)] public LinuxKvmDebugExitArch Debug;
        [FieldOffset(0)] public LinuxKvmMmioExit Mmio;
    }

    // struct kvm_run with the x86 kvm_sync_regs tail. The kernel stores Regs and Sregs on every return
    // and applies the groups DirtyRegs names before the next entry.
    [StructLayout(LayoutKind.Explicit)]
    internal struct LinuxKvmRun
    {
        [FieldOffset(0)] public byte RequestInterruptWindow;
        [FieldOffset(1)] public byte ImmediateExit;
        [FieldOffset(8)] public uint ExitReason;
        [FieldOffset(12)] public byte ReadyForInterruptInjection;
        [FieldOffset(13)] public byte IfFlag;
        [FieldOffset(14)] public ushort Flags;
        [FieldOffset(16)] public ulong Cr8;
        [FieldOffset(24)] public ulong ApicBase;
        [FieldOffset(32)] public LinuxKvmRunExit Exit;
        [FieldOffset(288)] public ulong ValidRegs;
        [FieldOffset(296)] public ulong DirtyRegs;
        [FieldOffset(304)] public LinuxKvmRegisters Regs;
        [FieldOffset(448)] public LinuxKvmSpecialRegisters Sregs;
    }
}
