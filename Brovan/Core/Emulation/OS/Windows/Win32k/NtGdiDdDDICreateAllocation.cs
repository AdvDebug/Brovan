using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICreateAllocation : IWinSyscall
    {
        private const int OffsetResource = 4;
        private const int OffsetGlobalShare = 8;

        private const uint FlagCreateResource = 0x1;
        private const uint FlagCreateShared = 0x2;
        private const uint FlagNonSecure = 0x4;
        private const uint FlagCreateProtected = 0x8;
        private const uint FlagRestrictSharedAccess = 0x10;
        private const uint FlagExistingSysMem = 0x20;
        private const uint FlagNtSecuritySharing = 0x40;
        private const uint FlagCreateWriteCombined = 0x100;
        private const uint FlagCreateCached = 0x200;
        private const uint FlagSwapChainBackBuffer = 0x400;
        private const uint FlagOpenCrossAdapter = 0x1000;
        private const uint FlagStandardAllocation = 0x10000;

        private const uint SupportedFlags = FlagCreateResource | FlagCreateShared | FlagNonSecure | FlagRestrictSharedAccess
            | FlagNtSecuritySharing | FlagSwapChainBackBuffer;

        private const uint PrivilegedFlags = FlagCreateProtected | FlagCreateWriteCombined | FlagCreateCached | FlagOpenCrossAdapter;

        // NT: wow64win does not copy Flags back, so only a 64-bit caller sees FlagZeroed.
        private const uint FlagZeroed = 0x4000;

        // The checks follow WarpKMCreateAllocation and WARPKMALLOCATION::Initialize.
        private const int WarpAllocationSize = 96;
        private const int OffsetWarpWidth = 4;
        private const int OffsetWarpHeight = 8;
        private const int OffsetWarpDepth = 12;
        private const int OffsetWarpFormat = 16;
        private const int OffsetWarpPitch = 20;
        private const int OffsetWarpBytes = 24;
        private const int OffsetWarpFlags = 88;
        private const uint WarpKindBuffer = 1;
        private const uint WarpFlagsSingleRow = 0x410000;
        private const uint WarpFlagsPresentEvents = 0x11;
        private const uint MaxWidth = 0x800000;
        private const uint MaxHeight = 0x800000;
        private const uint MaxDepth = 0x800;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            bool Wide = PointerSize == 8;
            int OffsetRuntimeData = Wide ? 16 : 12;
            int OffsetDriverDataSize = Wide ? 40 : 24;
            int OffsetCount = Wide ? 44 : 28;
            int OffsetInfos = Wide ? 48 : 32;
            int OffsetFlags = Wide ? 56 : 36;

            Span<byte> Arguments = stackalloc byte[60];
            Arguments = Arguments.Slice(0, OffsetFlags + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags));
            if ((Flags & PrivilegedFlags) != 0 || ((Flags & FlagExistingSysMem) != 0 && (Flags & FlagStandardAllocation) == 0)
                || ((Flags & FlagCreateShared) != 0 && (Flags & FlagCreateResource) == 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // A resource's runtime data is dropped, because Brovan does not open resources by handle.
            bool CreateResource = (Flags & FlagCreateResource) != 0;
            if (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetResource)) != 0 || (Flags & ~SupportedFlags) != 0
                || (!CreateResource && WinSysHelper.ReadPointerField(Arguments.Slice(OffsetRuntimeData), 0, (uint)PointerSize) != 0))
                return Instance.WinUnimplemented;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetDriverDataSize)) != 0
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetCount)) != 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong InfoPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetInfos), 0, (uint)PointerSize);
            Span<byte> Info = stackalloc byte[96];
            Info = Info.Slice(0, Wide ? 96 : 56);
            if (InfoPtr == 0 || !Instance.ReadMemory(InfoPtr, Info))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int OffsetSystemMem = PointerSize;
            int OffsetPrivate = 2 * PointerSize;
            int OffsetPrivateSize = 3 * PointerSize;
            int OffsetInfoFlags = 3 * PointerSize + 8;
            int OffsetGpuAddress = Wide ? 40 : 24;
            if (WinSysHelper.ReadPointerField(Info.Slice(OffsetSystemMem), 0, (uint)PointerSize) != 0 || BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetInfoFlags)) != 0)
                return Instance.WinUnimplemented;

            Span<byte> Warp = stackalloc byte[WarpAllocationSize];
            if (BinaryPrimitives.ReadUInt32LittleEndian(Info.Slice(OffsetPrivateSize)) != WarpAllocationSize
                || !Instance.ReadMemory(WinSysHelper.ReadPointerField(Info.Slice(OffsetPrivate), 0, (uint)PointerSize), Warp))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint WarpFlags = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpFlags));
            if ((WarpFlags & WarpFlagsPresentEvents) != 0)
                return Instance.WinUnimplemented;

            uint WarpBytes = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpBytes));
            if (WarpBytes == 0 || !IsValidShape(Warp, WarpFlags))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!DxgkStorage.TryCreate(Instance, Process, Instance.AlignToPageSize(WarpBytes), out DxgkStorage Storage))
                return NTSTATUS.STATUS_NO_MEMORY;

            Storage.Width = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpWidth));
            Storage.Height = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpHeight));
            Storage.Format = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpFormat));
            Storage.Pitch = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpPitch));

            DxgkResource Resource = null;
            if (CreateResource)
            {
                Resource = new() { Device = Device, Shared = (Flags & FlagCreateShared) != 0, NtSecuritySharing = (Flags & FlagNtSecuritySharing) != 0 };
                if (!Process.TryAdd(Resource, out _))
                {
                    Storage.Release(Instance, Process);
                    return NTSTATUS.STATUS_NO_MEMORY;
                }

                Device.Resources.Add(Resource);
            }

            DxgkAllocation Allocation = new()
            {
                Device = Device,
                Storage = Storage,
                Resource = Resource,
                SwapChainBackBuffer = (Flags & FlagSwapChainBackBuffer) != 0,
            };
            if (!Process.TryAdd(Allocation, out uint Handle))
            {
                Storage.Release(Instance, Process);
                if (Resource != null)
                    Process.Destroy(Instance, Resource);
                return NTSTATUS.STATUS_NO_MEMORY;
            }

            Device.Allocations.Add(Allocation);
            Resource?.Allocations.Add(Allocation);

            if (Instance.WinHelper.WriteUInt32(InfoPtr, Handle) && Instance.WinHelper.WriteUInt64(InfoPtr + (ulong)OffsetGpuAddress, 0)
                && Instance.WinHelper.WriteUInt32(ArgumentsPtr + OffsetResource, Resource?.Handle ?? 0)
                && Instance.WinHelper.WriteUInt32(ArgumentsPtr + OffsetGlobalShare, 0)
                && (!Wide || Instance.WinHelper.WriteUInt32(ArgumentsPtr + (ulong)OffsetFlags, Flags | FlagZeroed)))
                return NTSTATUS.STATUS_SUCCESS;

            Process.Destroy(Instance, (DxgkObject)Resource ?? Allocation);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static bool IsValidShape(ReadOnlySpan<byte> Warp, uint WarpFlags)
        {
            uint Kind = BinaryPrimitives.ReadUInt32LittleEndian(Warp);
            uint Width = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpWidth));
            uint Height = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpHeight));
            uint Depth = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(OffsetWarpDepth));
            return Kind == WarpKindBuffer || (WarpFlags & WarpFlagsSingleRow) != 0
                ? Height == 1 && Depth == 1
                : Width - 1 < MaxWidth && Height - 1 < MaxHeight && Depth - 1 < MaxDepth;
        }
    }
}
