using System;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation
{
    internal static unsafe class WhpNative
    {
        private const string Lib = "WinHvPlatform.dll";

        [DllImport(Lib)]
        public static extern int WHvGetCapability(WhvCapabilityCode CapabilityCode, void* CapabilityBuffer,
            uint CapabilityBufferSizeInBytes, uint* WrittenSizeInBytes);

        [DllImport(Lib)]
        public static extern int WHvCreatePartition(out IntPtr Partition);

        [DllImport(Lib)]
        public static extern int WHvSetupPartition(IntPtr Partition);

        [DllImport(Lib)]
        public static extern int WHvDeletePartition(IntPtr Partition);

        [DllImport(Lib)]
        public static extern int WHvSetPartitionProperty(IntPtr Partition, WhvPartitionPropertyCode PropertyCode,
            void* PropertyBuffer, uint PropertyBufferSizeInBytes);

        [DllImport(Lib)]
        public static extern int WHvMapGpaRange(IntPtr Partition, void* SourceAddress, ulong GuestAddress,
            ulong SizeInBytes, WhvMapGpaRangeFlags Flags);

        [DllImport(Lib)]
        public static extern int WHvUnmapGpaRange(IntPtr Partition, ulong GuestAddress, ulong SizeInBytes);

        [DllImport(Lib)]
        public static extern int WHvCreateVirtualProcessor(IntPtr Partition, uint VpIndex, uint Flags);

        [DllImport(Lib)]
        public static extern int WHvDeleteVirtualProcessor(IntPtr Partition, uint VpIndex);

        [DllImport(Lib)]
        public static extern int WHvRunVirtualProcessor(IntPtr Partition, uint VpIndex, void* ExitContext,
            uint ExitContextSizeInBytes);

        [DllImport(Lib)]
        public static extern int WHvCancelRunVirtualProcessor(IntPtr Partition, uint VpIndex, uint Flags);

        [DllImport(Lib)]
        public static extern int WHvGetVirtualProcessorRegisters(IntPtr Partition, uint VpIndex,
            uint* RegisterNames, uint RegisterCount, WhvRegisterValue* RegisterValues);

        [DllImport(Lib)]
        public static extern int WHvSetVirtualProcessorRegisters(IntPtr Partition, uint VpIndex,
            uint* RegisterNames, uint RegisterCount, WhvRegisterValue* RegisterValues);

        [DllImport("winmm.dll")]
        public static extern uint timeBeginPeriod(uint uPeriod);

        [DllImport("winmm.dll")]
        public static extern uint timeEndPeriod(uint uPeriod);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;

        public static bool Failed(int hr) => hr < 0;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct WhvRegisterValue
    {
        [FieldOffset(0)] public ulong Low;
        [FieldOffset(8)] public ulong High;

        public static WhvRegisterValue FromReg64(ulong value) => new WhvRegisterValue { Low = value };

        public static WhvRegisterValue FromSegment(ulong @base, uint limit, ushort selector, ushort attributes)
            => new WhvRegisterValue
            {
                Low = @base,
                High = limit | ((ulong)selector << 32) | ((ulong)attributes << 48),
            };

        public static WhvRegisterValue FromTable(ulong @base, ushort limit)
            => new WhvRegisterValue
            {
                Low = (ulong)limit << 48,
                High = @base,
            };
    }

    [StructLayout(LayoutKind.Explicit, Size = 144)]
    internal struct WhvRunVpExitContext
    {
        [FieldOffset(0)] public WhvRunVpExitReason ExitReason;
        [FieldOffset(68)] public uint MemAccessInfo;
        [FieldOffset(72)] public ulong MemGpa;
    }
}
