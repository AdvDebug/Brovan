using System.Buffers.Binary;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICreateContextVirtual : IWinSyscall
    {
        private const int OffsetNode = 4;
        private const int OffsetEngineAffinity = 8;
        private const int OffsetFlags = 12;
        private const int OffsetPrivate = 16;

        // NT: NoKmdAccess and TestContext need test signing, and the bits above them are reserved.
        private const uint FlagsRefused = 0xFFFFFFE0;

        // NullRendering, InitialData, SynchronizationOnly and HwQueueSupported.
        private const uint FlagsUnmodeled = 0x1B;

        // NT reads a 16-byte private block as the places to write the command buffer address and size (DXGCONTEXT::Initialize).
        private const int CommandBufferBlockSize = 16;
        private const ulong MinCommandBufferTarget = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetPrivateSize = OffsetPrivate + PointerSize;
            int OffsetContext = OffsetPrivateSize + 8;

            Span<byte> Arguments = stackalloc byte[40];
            Arguments = Arguments.Slice(0, OffsetContext + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags));
            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if ((Flags & FlagsRefused) != 0 || !Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT: an engine affinity above bit 0 names a physical adapter that is not there.
            if (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetEngineAffinity)) > 1
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetNode)) >= Win32kDxgk.WarpNodeCount(Instance))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((Flags & FlagsUnmodeled) != 0)
                return Instance.WinUnimplemented;

            ulong PrivatePtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetPrivate), 0, (uint)PointerSize);
            uint PrivateSize = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetPrivateSize));
            if ((PrivatePtr == 0) != (PrivateSize == 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (PrivateSize > MemoryBudget.PooledIoBytes)
                return NTSTATUS.STATUS_NO_MEMORY;

            bool HasCommandBuffer = PrivateSize == CommandBufferBlockSize;
            Span<byte> Block = stackalloc byte[CommandBufferBlockSize];
            if (HasCommandBuffer ? !Instance.ReadMemory(PrivatePtr, Block) : !IsReadable(Instance, PrivatePtr, PrivateSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkContext Context = new() { Device = Device };
            if (!Process.TryAdd(Context, out uint Handle))
                return NTSTATUS.STATUS_NO_MEMORY;

            Device.Contexts.Add(Context);

            NTSTATUS Status = HasCommandBuffer ? AllocateCommandBuffer(Instance, Context, Block) : NTSTATUS.STATUS_SUCCESS;
            if (Status == NTSTATUS.STATUS_SUCCESS && !Instance.WinHelper.WriteUInt32(ArgumentsPtr + (ulong)OffsetContext, Handle))
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Status != NTSTATUS.STATUS_SUCCESS)
                Process.Destroy(Instance, Context);

            return Status;
        }

        // The kernel copies the whole block, so an unreadable one fails here too.
        private static bool IsReadable(BinaryEmulator Instance, ulong Address, uint Size)
        {
            for (uint Offset = 0; Offset < Size; Offset += (uint)NtReadFile.IoChunkBytes)
            {
                if (Instance.WinHelper.ReadMemorySpan(Address + Offset, Math.Min(Size - Offset, (uint)NtReadFile.IoChunkBytes)).IsEmpty)
                    return false;
            }

            return true;
        }

        // The targets are 64-bit for a 32-bit caller too, because the kernel reads the block as it is.
        private static NTSTATUS AllocateCommandBuffer(BinaryEmulator Instance, DxgkContext Context, ReadOnlySpan<byte> Block)
        {
            ulong AddressTarget = BinaryPrimitives.ReadUInt64LittleEndian(Block);
            ulong SizeTarget = BinaryPrimitives.ReadUInt64LittleEndian(Block.Slice(8));

            ulong Base = 0;
            ulong Size = DxgkContext.DmaBufferSize;
            NTSTATUS Status = NtAllocateVirtualMemory.Allocate(Instance, ref Base, ref Size, NtAllocateVirtualMemory.MemCommit | NtAllocateVirtualMemory.MemReserve,
                WinSysHelper.PAGE_READWRITE, NtAllocateVirtualMemory.AddressRequirements.None);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Context.CommandBuffer = Base;

            if (SizeTarget == 0 || AddressTarget == 0 || !Instance.WinHelper.TryReadUInt64(SizeTarget, out ulong Capacity) || Capacity < MinCommandBufferTarget)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance.WinHelper.WriteUInt64(AddressTarget, Base) && Instance.WinHelper.WriteUInt64(SizeTarget, Size)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
