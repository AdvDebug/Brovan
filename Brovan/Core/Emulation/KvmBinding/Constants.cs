using System;

namespace Brovan.Core.Emulation
{
    public enum KvmErrors
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
    public enum KvmMemoryPermission
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

    public static class KvmConstants
    {
        public const int ExpectedApiVersion = 12;

        public const uint KvmIoGetApiVersion = 0xAE00;
        public const uint KvmIoCreateVm = 0xAE01;
        public const uint KvmIoCheckExtension = 0xAE03;
        public const uint KvmIoGetVcpuMmapSize = 0xAE04;
        public const uint KvmIoGetSupportedCpuid = 0xC008AE05;

        public const uint KvmIoSetUserMemoryRegion = 0x4020AE46;
        public const uint KvmIoSetTssAddress = 0xAE47;
        public const uint KvmIoCreateVcpu = 0xAE41;

        public const uint KvmIoRun = 0xAE80;
        public const uint KvmIoGetRegisters = 0x8090AE81;
        public const uint KvmIoSetRegisters = 0x4090AE82;
        public const uint KvmIoGetSpecialRegisters = 0x8138AE83;
        public const uint KvmIoSetSpecialRegisters = 0x4138AE84;
        public const uint KvmIoTranslate = 0xC018AE85;
        public const uint KvmIoGetMsrs = 0xC008AE88;
        public const uint KvmIoSetMsrs = 0x4008AE89;
        public const uint KvmIoGetFpu = 0x81A0AE8C;
        public const uint KvmIoSetFpu = 0x41A0AE8D;
        public const uint KvmIoGetCpuid2 = 0xC008AE91;
        public const uint KvmIoSetCpuid2 = 0x4008AE90;
        public const uint KvmIoGetXsave = 0x9000AEA4;
        public const uint KvmIoSetXsave = 0x5000AEA5;
        public const uint KvmIoGetVcpuEvents = 0x8040AE9F;
        public const uint KvmIoSetVcpuEvents = 0x4040AEA0;
        public const uint KvmIoGetDebugRegisters = 0x8080AEA1;
        public const uint KvmIoSetDebugRegisters = 0x4080AEA2;
        public const uint KvmIoGetTscKhz = 0xAEA3;

        public const int CapNrMemslots = 10;
        public const int CapGetTscKhz = 61;
        public const int CapMaxVcpus = 66;
        public const int CapSyncRegs = 74;
        public const int CapXsave = 84;
        public const int CapImmediateExit = 136;

        public const ulong SyncGeneralRegisters = 1UL << 0;
        public const ulong SyncSpecialRegisters = 1UL << 1;

        public const uint MsrTsc = 0x10;

        public const uint MemSlotReadOnly = 0x00000001u;

        public const int ExitUnknown = 0;
        public const int ExitException = 1;
        public const int ExitIo = 2;
        public const int ExitHypercall = 3;
        public const int ExitDebug = 4;
        public const int ExitHlt = 5;
        public const int ExitMmio = 6;
        public const int ExitIrqWindowOpen = 7;
        public const int ExitShutdown = 8;
        public const int ExitFailEntry = 9;
        public const int ExitIntr = 10;
        public const int ExitSetTpr = 11;
        public const int ExitTprAccess = 12;
        public const int ExitInternalError = 17;

        public const uint MsrStar = 0xC0000081;
        public const uint MsrLstar = 0xC0000082;
        public const uint MsrSyscallMask = 0xC0000084;
        public const uint MsrEfer = 0xC0000080;

        public const ulong PageShift = 12;
        public const ulong PageSize = 1UL << (int)PageShift;
        public const ulong PageMask = PageSize - 1;

        public const ulong InternalPageTableBase = 0x0000007000000000UL;
        public const ulong PageTableEntryPresent = 1UL << 0;
        public const ulong PageTableEntryWritable = 1UL << 1;
        public const ulong PageTableEntryUser = 1UL << 2;
        public const ulong PageTableEntryAddressMask = 0x000FFFFFFFFFF000UL;

        public const ushort KernelCodeSelector = 0x08;
        public const ushort UserDataSelector = 0x2B;
        public const ushort UserCodeSelector = 0x33;
        public const ushort TssSelector = 0x38;

        public const int ExceptionVectorCount = 32;
        public const ulong ExceptionStubStride = 8;
        public const byte ExceptionIstIndex = 1;

        public const byte ExceptionGateAttributes = 0xEE;
    }
}
