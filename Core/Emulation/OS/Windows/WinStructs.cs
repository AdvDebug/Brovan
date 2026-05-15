using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Helpers;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Brovan.Core.Emulation.OS.Windows
{
    [StructLayout(LayoutKind.Explicit)]
    public struct UNICODE_STRING
    {
        [FieldOffset(0)]
        public ushort Length;

        [FieldOffset(2)]
        public ushort MaximumLength;

        [FieldOffset(4)]
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct UNICODE_STRING64
    {
        [FieldOffset(0)]
        public ushort Length;

        [FieldOffset(2)]
        public ushort MaximumLength;

        [FieldOffset(8)]
        public ulong Buffer;
    }

    [StructLayout(LayoutKind.Explicit, Size = 48)]
    public struct OBJECT_ATTRIBUTES64
    {
        [FieldOffset(0)]
        public uint Length;

        [FieldOffset(8)]
        public ulong RootDirectory;

        [FieldOffset(16)]
        public ulong ObjectName;

        [FieldOffset(24)]
        public uint Attributes;

        [FieldOffset(32)]
        public ulong SecurityDescriptor;

        [FieldOffset(40)]
        public ulong SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_REGION_INFORMATION
    {
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint RegionType;
        public ulong RegionSize;
        public ulong CommitSize;
        public ulong PartitionId;
        public ulong NodePreference;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_IMAGE_EXTENSION_INFORMATION
    {
        public MEMORY_IMAGE_EXTENSION_TYPE ExtensionType;
        public uint Flags;
        public ulong ExtensionImageBaseRva;
        public ulong ExtensionSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_WORKING_SET_EX_INFORMATION
    {
        public ulong VirtualAddress;
        public ulong VirtualAttributes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct KEY_BASIC_INFORMATION
    {
        public long LastWriteTime;
        public uint TitleIndex;
        public uint NameLength;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public uint LowPart;

        [FieldOffset(4)]
        public int HighPart;

        [FieldOffset(0)]
        public long QuadPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public uint ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;

        public ulong Rip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public ushort Reserved; // padding so RegionSize stays aligned
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint Reserved2; // tail padding to 48 bytes
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_IMAGE_INFORMATION
    {
        public ulong ImageBase;
        public ulong SizeOfImage;

        public ulong Flags;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct KEY_NAME_INFORMATION
    {
        public uint NameLength;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PROCESS_TLS_INFORMATION64
    {
        public uint Flags;
        public uint OperationType;
        public uint ThreadDataCount;
        public uint TlsIndexOrVectorLength;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct THREAD_TLS_INFORMATION64
    {
        public uint Flags;
        public uint Padding;
        public ulong TlsData;
        public ulong ThreadId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct GENERIC_MAPPING
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    public enum MUTANT_INFORMATION_CLASS : uint
    {
        MutantBasicInformation = 0,
        MutantOwnerInformation = 1
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MUTANT_BASIC_INFORMATION
    {
        public int CurrentCount;
        public byte OwnedByCaller;
        public byte AbandonedState;
        public ushort Reserved;
    }

    public enum SEMAPHORE_INFORMATION_CLASS : uint
    {
        SemaphoreBasicInformation = 0
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SEMAPHORE_BASIC_INFORMATION
    {
        public int CurrentCount;
        public int MaximumCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct OBJECT_BASIC_INFORMATION_DATA
    {
        public uint Attributes;
        public uint GrantedAccess;
        public uint HandleCount;
        public uint PointerCount;
        public uint PagedPoolCharge;
        public uint NonPagedPoolCharge;
        public uint Reserved1;
        public uint Reserved2;
        public uint Reserved3;
        public uint NameInfoSize;
        public uint TypeInfoSize;
        public uint SecurityDescriptorSize;
        public long CreationTime;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct OBJECT_TYPE_INFORMATION64
    {
        public UNICODE_STRING64 TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct OBJECT_TYPE_INFORMATION32
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    public struct LARGE_STRING64
    {
        [FieldOffset(0)]
        public uint Length;

        [FieldOffset(4)]
        public uint MaximumLength;

        [FieldOffset(8)]
        public ulong Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_BATTERY_STATE
    {
        public bool AcOnLine;
        public bool BatteryPresent;
        public bool Charging;
        public bool Discharging;

        [EmulatedInline(3)]
        public byte[] Spare1;

        public byte Tag;
        public uint MaxCapacity;
        public uint RemainingCapacity;
        public uint Rate;
        public uint EstimatedTime;
        public uint DefaultAlert1;
        public uint DefaultAlert2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BATTERY_REPORTING_SCALE
    {
        public uint Granularity;
        public uint Capacity;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_POWER_CAPABILITIES
    {
        public bool PowerButtonPresent;
        public bool SleepButtonPresent;
        public bool LidPresent;
        public bool SystemS1;
        public bool SystemS2;
        public bool SystemS3;
        public bool SystemS4;
        public bool SystemS5;
        public bool HiberFilePresent;
        public bool FullWake;
        public bool VideoDimPresent;
        public bool ApmPresent;
        public bool UpsPresent;
        public bool ThermalControl;
        public bool ProcessorThrottle;

        public byte ProcessorMinThrottle;
        public byte ProcessorThrottleScale;

        [EmulatedInline(4)]
        public byte[] Spare2;

        public byte ProcessorMaxThrottle;

        public bool FastSystemS4;
        public bool Hiberboot;
        public bool WakeAlarmPresent;
        public bool AoAc;
        public bool DiskSpinDown;

        [EmulatedInline(6)]
        public byte[] Spare3;

        public bool SystemBatteriesPresent;
        public bool BatteriesAreShortTerm;

        [EmulatedInline(3)]
        public BATTERY_REPORTING_SCALE[] BatteryScale;

        public int AcOnLineWake;
        public int SoftLidWake;
        public int RtcWake;
        public int MinDeviceWakeState;
        public int DefaultLowLatencyWake;
    }
}