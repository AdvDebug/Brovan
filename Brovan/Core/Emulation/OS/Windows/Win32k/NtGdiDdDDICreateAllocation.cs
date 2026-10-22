using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICreateAllocation : IWinSyscall
    {
        private const int OffsetResource = 4;

        // NT: wow64win does not copy Flags back, so only a 64-bit caller sees FlagZeroed.
        private const uint FlagZeroed = 0x4000;

        // The checks follow WarpKMCreateAllocation and WARPKMALLOCATION::Initialize.
        private const int WarpAllocationSize = 96;
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

            if (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetResource)) != 0
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags)) != 0
                || WinSysHelper.ReadPointerField(Arguments.Slice(OffsetRuntimeData), 0, (uint)PointerSize) != 0)
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

            uint WarpFlags = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(88));
            if ((WarpFlags & WarpFlagsPresentEvents) != 0)
                return Instance.WinUnimplemented;

            uint WarpBytes = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(24));
            if (WarpBytes == 0 || !IsValidShape(Warp, WarpFlags))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong Size = Instance.AlignToPageSize(WarpBytes);
            if (Size > Win32kDxgk.SharedSegmentSize - Process.AllocatedBytes)
                return NTSTATUS.STATUS_NO_MEMORY;

            IntPtr Storage = Instance._emulator.AllocateSharedStorage(Size);
            if (Storage == IntPtr.Zero)
                return NTSTATUS.STATUS_NO_MEMORY;

            DxgkAllocation Allocation = new() { Device = Device, Size = Size, Storage = Storage };
            if (!Process.TryAdd(Allocation, out uint Handle))
            {
                Instance._emulator.ReleaseSharedStorage(Storage);
                return NTSTATUS.STATUS_NO_MEMORY;
            }

            Process.AllocatedBytes += Size;
            Device.Allocations.Add(Allocation);

            if (Instance.WinHelper.WriteUInt32(InfoPtr, Handle) && Instance.WinHelper.WriteUInt64(InfoPtr + (ulong)OffsetGpuAddress, 0)
                && (!Wide || Instance.WinHelper.WriteUInt32(ArgumentsPtr + (ulong)OffsetFlags, FlagZeroed)))
                return NTSTATUS.STATUS_SUCCESS;

            Process.Destroy(Instance, Allocation);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static bool IsValidShape(ReadOnlySpan<byte> Warp, uint WarpFlags)
        {
            uint Kind = BinaryPrimitives.ReadUInt32LittleEndian(Warp);
            uint Width = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(4));
            uint Height = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(8));
            uint Depth = BinaryPrimitives.ReadUInt32LittleEndian(Warp.Slice(12));
            return Kind == WarpKindBuffer || (WarpFlags & WarpFlagsSingleRow) != 0
                ? Height == 1 && Depth == 1
                : Width - 1 < MaxWidth && Height - 1 < MaxHeight && Depth - 1 < MaxDepth;
        }
    }
}
