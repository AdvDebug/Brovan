using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDILock : IWinSyscall
    {
        private const int OffsetAllocation = 4;
        private const int OffsetNumPages = 12;
        private const int OffsetPages = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetData = OffsetPages + PointerSize;
            int OffsetGpuAddress = PointerSize == 8 ? 40 : 32;

            Span<byte> Arguments = stackalloc byte[48];
            Arguments = Arguments.Slice(0, OffsetGpuAddress + 8);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device)
                || !Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetAllocation)), Device, out DxgkAllocation Allocation)
                || Allocation.LockCount == uint.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetNumPages)) != 0)
                return Instance.WinUnimplemented;

            if (Allocation.View == 0)
            {
                if (!DxgkProcess.TryMapStorage(Instance, Allocation.Storage.Memory, Allocation.Storage.Size, out ulong View))
                    return NTSTATUS.STATUS_NO_MEMORY;

                Allocation.View = View;
            }

            if (!Instance.WinHelper.WritePointer(ArgumentsPtr + (ulong)OffsetData, Allocation.View)
                || !Instance.WinHelper.WriteUInt64(ArgumentsPtr + (ulong)OffsetGpuAddress, 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Allocation.LockCount++;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
