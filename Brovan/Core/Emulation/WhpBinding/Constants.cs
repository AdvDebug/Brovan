using System;

namespace Brovan.Core.Emulation
{
    public enum WhpErrors
    {
        Ok = 0,
        NoMemory,
        InvalidArgument,
        InvalidArchitecture,
        InvalidMode,
        MemoryReadUnmapped,
        MemoryWriteUnmapped,
        MemoryFetchUnmapped,
        MemoryReadProtected,
        MemoryWriteProtected,
        MemoryFetchProtected,
        InvalidInstruction,
        HookError,
        ResourceError,
        Exception,
        InternalError,
    }

    [Flags]
    public enum WhpMemoryPermission
    {
        None = 0,
        Read = 1,
        Write = 2,
        Execute = 4,
        ReadWrite = Read | Write,
        WriteExecute = Write | Execute,
        ReadExecute = Read | Execute,
        All = Read | Write | Execute,
    }

    internal enum WhvCapabilityCode : uint
    {
        HypervisorPresent = 0x00000000,
        Features = 0x00000001,
        ProcessorFeatures = 0x00001001,
    }

    internal enum WhvPartitionPropertyCode : uint
    {
        ExtendedVmExits = 0x00000001,
        ExceptionExitBitmap = 0x00000002,
        ProcessorFeatures = 0x00001001,
        ProcessorCount = 0x00001fff,
    }

    [Flags]
    internal enum WhvMapGpaRangeFlags : uint
    {
        None = 0x00000000,
        Read = 0x00000001,
        Write = 0x00000002,
        Execute = 0x00000004,
        TrackDirtyPages = 0x00000008,
    }

    internal enum WhvRunVpExitReason : uint
    {
        None = 0x00000000,
        MemoryAccess = 0x00000001,
        X64IoPortAccess = 0x00000002,
        UnrecoverableException = 0x00000004,
        InvalidVpRegisterValue = 0x00000005,
        UnsupportedFeature = 0x00000006,
        X64InterruptWindow = 0x00000007,
        X64Halt = 0x00000008,
        X64ApicEoi = 0x00000009,
        X64MsrAccess = 0x00001000,
        X64Cpuid = 0x00001001,
        Exception = 0x00001002,
        X64Rdtsc = 0x00001003,
        Canceled = 0x00002001,
    }

    internal enum WhvMemoryAccessType : uint
    {
        Read = 0,
        Write = 1,
        Execute = 2,
    }

    internal enum WhvRegisterName : uint
    {
        Rax = 0x00000000,
        Rcx = 0x00000001,
        Rdx = 0x00000002,
        Rbx = 0x00000003,
        Rsp = 0x00000004,
        Rbp = 0x00000005,
        Rsi = 0x00000006,
        Rdi = 0x00000007,
        R8 = 0x00000008,
        R9 = 0x00000009,
        R10 = 0x0000000A,
        R11 = 0x0000000B,
        R12 = 0x0000000C,
        R13 = 0x0000000D,
        R14 = 0x0000000E,
        R15 = 0x0000000F,
        Rip = 0x00000010,
        Rflags = 0x00000011,

        Es = 0x00000012,
        Cs = 0x00000013,
        Ss = 0x00000014,
        Ds = 0x00000015,
        Fs = 0x00000016,
        Gs = 0x00000017,
        Ldtr = 0x00000018,
        Tr = 0x00000019,
        Idtr = 0x0000001A,
        Gdtr = 0x0000001B,

        Cr0 = 0x0000001C,
        Cr2 = 0x0000001D,
        Cr3 = 0x0000001E,
        Cr4 = 0x0000001F,
        Cr8 = 0x00000020,

        Dr0 = 0x00000021,
        Dr1 = 0x00000022,
        Dr2 = 0x00000023,
        Dr3 = 0x00000024,
        Dr6 = 0x00000025,
        Dr7 = 0x00000026,

        Efer = 0x00002001,
        Star = 0x00002008,
        Lstar = 0x00002009,
        Sfmask = 0x0000200B,
    }

    public static class WhpConstants
    {
        public const ulong PageShift = 12;
        public const ulong PageSize = 1UL << (int)PageShift;
        public const ulong PageMask = PageSize - 1;

        public const ulong InternalPageTableBase = 0x0000007000000000UL;
        public const ulong PageTableEntryPresent = 1UL << 0;
        public const ulong PageTableEntryWritable = 1UL << 1;
        public const ulong PageTableEntryUser = 1UL << 2;
        public const ulong PageTableEntryAddressMask = 0x000FFFFFFFFFF000UL;

        public const ushort KernelCodeSelector = 0x08;
        public const ushort KernelDataSelector = 0x10;
        public const ushort UserCodeSelector32 = 0x1B;
        public const ushort UserDataSelector32 = 0x23;
        public const ushort UserDataSelector = 0x2B;
        public const ushort UserCodeSelector = 0x33;
        public const ushort UserFsSelector32 = 0x3B;
        public const ushort UserGsSelector32 = 0x43;
        public const ushort TssSelector = 0x60;

        public const ushort GdtLimit = 0x6F;

        public const int ExceptionVectorCount = 256;
        public const uint FirstSoftwareInterruptVector = 32;
        public const ulong ExceptionStubStride = 8;
        public const byte ExceptionIstIndex = 1;
        public const byte ExceptionGateAttributes = 0xEE;
    }
}
