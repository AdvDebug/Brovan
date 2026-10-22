using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICreatePagingQueue : IWinSyscall
    {
        private const int OffsetPagingQueue = 8;
        private const int OffsetSyncObject = 12;
        private const int OffsetFenceAddress = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetAdapterIndex = OffsetFenceAddress + PointerSize;

            Span<byte> Arguments = stackalloc byte[32];
            Arguments = Arguments.Slice(0, OffsetAdapterIndex + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device)
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetAdapterIndex)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = DxgkFence.TryCreate(Instance, Process, Device, DxgkPagingQueue.InitialFenceValue, out DxgkFence Fence);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Fence.OwnedByPagingQueue = true;
            DxgkPagingQueue Queue = new() { Device = Device, Fence = Fence };
            if (!Process.TryAdd(Queue, out uint Handle))
            {
                Process.Destroy(Instance, Fence);
                return NTSTATUS.STATUS_NO_MEMORY;
            }

            Device.PagingQueues.Add(Queue);

            Span<byte> Outputs = Arguments.Slice(OffsetPagingQueue, OffsetAdapterIndex - OffsetPagingQueue);
            BinaryPrimitives.WriteUInt32LittleEndian(Outputs, Handle);
            BinaryPrimitives.WriteUInt32LittleEndian(Outputs.Slice(OffsetSyncObject - OffsetPagingQueue), Fence.Handle);
            WinSysHelper.WritePointerField(Outputs.Slice(OffsetFenceAddress - OffsetPagingQueue), 0, (uint)PointerSize, Fence.CpuAddress);

            if (Instance.WriteMemory(ArgumentsPtr + OffsetPagingQueue, Outputs))
                return NTSTATUS.STATUS_SUCCESS;

            Process.Destroy(Instance, Queue);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
