using System.Buffers.Binary;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal enum DxgkAdapterKind
    {
        Display,
        BasicRender,
    }

    internal sealed class DxgkAdapter
    {
        internal DxgkAdapterKind Kind { get; init; }
        internal uint LuidLowPart { get; init; }
        internal int LuidHighPart { get; init; }
        internal uint SourceCount { get; init; }
        internal uint AdapterType { get; init; }
        internal uint BusType { get; init; }
        internal uint VendorId { get; init; }
        internal uint DeviceId { get; init; }
        internal string Description { get; init; }
        internal string DeviceInstanceId { get; init; }
        internal string DeviceInterface { get; init; }
        internal string UniqueId { get; init; }
        internal ulong DedicatedVideoMemory { get; init; }

        internal bool MatchesLuid(uint LowPart, int HighPart) => LowPart == LuidLowPart && HighPart == LuidHighPart;
    }

    /// <summary>
    /// BrovVulk draws through the display adapter. It has no Windows D3D driver, so D3D renders on Basic Render.
    /// </summary>
    internal static class Win32kDxgk
    {
        internal const uint WddmVersion = 0xC80;

        private const uint RenderSupported = 0x1;
        private const uint DisplaySupported = 0x2;
        private const uint SoftwareDevice = 0x4;
        private const uint AcgSupported = 0x100;

        // A guest that sizes its pools from the kernel view gets the same answer on every host, because the
        // number is not the host GPU's. DXGI reports the real device through BrovVulk.
        private const ulong DisplayDedicatedVideoMemory = 4UL << 30;

        // NT: the shared segment of every adapter is half of physical memory.
        internal static ulong SharedSegmentSize => MemoryBudget.GuestPhysicalBytes / 2;

        // NT: an enumeration with no array reports the most adapters it can list.
        internal const uint MaxEnumAdapters = 34;

        // NT: StartGPU in BasicRender.sys.
        private const uint MinWarpNodes = 3;
        private const uint MaxWarpNodes = 62;

        internal static uint WarpNodeCount(BinaryEmulator Instance) => Math.Clamp((uint)Instance.WinHelper.ProcessorCount + 1, MinWarpNodes, MaxWarpNodes);

        // D3DKMT_ADAPTERINFO: hAdapter, LUID, NumOfSources, bPrecisePresentRegionsPreferred.
        internal const int AdapterInfoSize = 20;

        private const string DisplayInterfaceClass = "{1024e4c9-47c9-48d3-b4a8-f9df78523b53}";

        internal static readonly DxgkAdapter Display = new()
        {
            Kind = DxgkAdapterKind.Display,
            LuidLowPart = 0xB00F,
            LuidHighPart = 1,
            SourceCount = 1,
            AdapterType = DisplaySupported,
            BusType = 1,
            Description = "Brovan Display Adapter",
            DeviceInstanceId = @"PCI\VEN_0000&DEV_0000&SUBSYS_00000000&REV_00",
            DeviceInterface = @"\\?\PCI#VEN_0000&DEV_0000&SUBSYS_00000000&REV_00#0#" + DisplayInterfaceClass,
            UniqueId = "{B73ADCCD-99F6-4B2B-831E-47E106405C20}",
            DedicatedVideoMemory = DisplayDedicatedVideoMemory,
        };

        internal static readonly DxgkAdapter BasicRender = new()
        {
            Kind = DxgkAdapterKind.BasicRender,
            LuidLowPart = 0xB010,
            LuidHighPart = 1,
            SourceCount = 0,
            AdapterType = RenderSupported | SoftwareDevice | AcgSupported,
            BusType = 3,
            VendorId = 0x1414,
            DeviceId = 0x8C,
            Description = "Microsoft Basic Render Driver",
            DeviceInstanceId = @"ROOT\BasicRender\0000",
            DeviceInterface = @"\\?\ROOT#BasicRender#0000#" + DisplayInterfaceClass,
            UniqueId = "{FD011EF1-249B-4D83-AA9C-CC5C9FDADA67}",
        };

        private static readonly DxgkAdapter[] Adapters = { Display, BasicRender };

        internal static DxgkAdapter FindByLuid(ReadOnlySpan<byte> Luid)
        {
            uint LowPart = BinaryPrimitives.ReadUInt32LittleEndian(Luid);
            int HighPart = BinaryPrimitives.ReadInt32LittleEndian(Luid.Slice(4));
            foreach (DxgkAdapter Adapter in Adapters)
            {
                if (Adapter.MatchesLuid(LowPart, HighPart))
                    return Adapter;
            }

            return null;
        }

        internal static bool TryReadHandleArgument(BinaryEmulator Instance, out uint Handle)
        {
            Handle = 0;
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            return ArgumentsPtr != 0 && Instance.WinHelper.TryReadUInt32(ArgumentsPtr, out Handle);
        }

        internal static bool TryGetHandleArgument<T>(BinaryEmulator Instance, out T Object) where T : class
        {
            Object = null;
            return TryReadHandleArgument(Instance, out uint Handle) && Instance.WinHelper.DxgkProcess.TryGet(Handle, out Object);
        }

        internal static void WriteLuid(Span<byte> Destination, DxgkAdapter Adapter)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0, 4), Adapter.LuidLowPart);
            BinaryPrimitives.WriteInt32LittleEndian(Destination.Slice(4, 4), Adapter.LuidHighPart);
        }

        // D3DKMT_ENUMADAPTERS2 and 3: pAdapters follows NumAdapters on the guest pointer alignment.
        internal static NTSTATUS EnumerateToArray(BinaryEmulator Instance, int OffsetNumAdapters)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            Span<byte> Arguments = stackalloc byte[24];
            Arguments = Arguments.Slice(0, OffsetNumAdapters + 2 * PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Capacity = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetNumAdapters));
            ulong AdaptersPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetNumAdapters + PointerSize), 0, (uint)PointerSize);
            return Enumerate(Instance, ArgumentsPtr + (ulong)OffsetNumAdapters, AdaptersPtr, Capacity);
        }

        internal static NTSTATUS Enumerate(BinaryEmulator Instance, ulong CountPtr, ulong ArrayPtr, uint Capacity)
        {
            uint Count = MaxEnumAdapters;
            if (ArrayPtr != 0)
            {
                NTSTATUS Status = TryEnumerate(Instance, ArrayPtr, Capacity, out Count);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            return Instance.WinHelper.WriteUInt32(CountPtr, Count) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // NT: every enumeration call opens new adapter handles.
        private static NTSTATUS TryEnumerate(BinaryEmulator Instance, ulong ArrayPtr, uint Capacity, out uint Count)
        {
            Count = (uint)Adapters.Length;
            if (Capacity < Count)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            int Size = Adapters.Length * AdapterInfoSize;
            Span<byte> Infos = Instance.WinHelper.Shared.GetSpan((ulong)Size).Slice(0, Size);
            Infos.Clear();

            for (int Index = 0; Index < Adapters.Length; Index++)
            {
                if (!Process.TryAdd(Adapters[Index], out uint Handle))
                {
                    CloseWritten(Process, Infos, Index);
                    return NTSTATUS.STATUS_NO_MEMORY;
                }

                Span<byte> Info = Infos.Slice(Index * AdapterInfoSize, AdapterInfoSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Info, Handle);
                WriteLuid(Info.Slice(4, 8), Adapters[Index]);
                BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(12, 4), Adapters[Index].SourceCount);
            }

            if (Instance.WriteMemory(ArrayPtr, Infos))
                return NTSTATUS.STATUS_SUCCESS;

            CloseWritten(Process, Infos, Adapters.Length);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static void CloseWritten(DxgkProcess Process, ReadOnlySpan<byte> Infos, int Opened)
        {
            for (int Index = 0; Index < Opened; Index++)
                Process.TryRemove<DxgkAdapter>(BinaryPrimitives.ReadUInt32LittleEndian(Infos.Slice(Index * AdapterInfoSize)));
        }

        internal const int HybridQuerySize = 20;
        internal const int OffsetHybridQueryType = 16;
        internal const uint HybridQueryAdapter = 0;
        internal const uint HybridQueryProcess1 = 1;
        internal const uint HybridQueryProcess2 = 2;

        internal const uint PropertyDefaultHighPerformanceAdapter = 2;
        private const uint PropertyPresentDurationPlane = 3;
        private const uint PropertyPresentStatsDwm2 = 4;
        private const uint PropertyBoostedVSyncEligible = 5;

        internal static bool TryReadProperties(BinaryEmulator Instance, ulong ArgumentsPtr, bool Set, out uint Type, out ulong DataPtr)
        {
            Type = 0;
            DataPtr = 0;

            // NT: Get checks only the low half of Reserved, and wow64win passes a 32-bit Get its pointer at 12.
            bool Wide = Instance.WinHelper.PointerSize == 8;
            Span<byte> Arguments = stackalloc byte[24];
            Arguments = Arguments.Slice(0, Wide ? 24 : 20);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return false;

            Type = BinaryPrimitives.ReadUInt32LittleEndian(Arguments);
            uint Size = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(4));
            ulong Reserved = Set ? BinaryPrimitives.ReadUInt64LittleEndian(Arguments.Slice(8)) : BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(8));
            DataPtr = WinSysHelper.ReadPointerField(Arguments.Slice(Wide || Set ? 16 : 12), 0, (uint)Instance.WinHelper.PointerSize);

            uint MinimumSize = Type switch
            {
                PropertyPresentDurationPlane => 32,
                PropertyPresentStatsDwm2 when !Set => 88,
                <= PropertyDefaultHighPerformanceAdapter or PropertyBoostedVSyncEligible => 16,
                _ => uint.MaxValue,
            };

            return DataPtr != 0 && Size != 0 && Reserved == 0 && Size >= MinimumSize;
        }
    }
}
