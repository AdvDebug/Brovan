using System.Buffers;
using System.Buffers.Binary;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIUnlock : IWinSyscall
    {
        private const int OffsetCount = 4;
        private const int OffsetList = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;

            Span<byte> Arguments = stackalloc byte[16];
            Arguments = Arguments.Slice(0, OffsetList + PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetCount));
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device) || Count == 0 || Count > MemoryBudget.DxgkHandles)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong ListPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetList), 0, (uint)PointerSize);
            DxgkAllocation[] Rented = ArrayPool<DxgkAllocation>.Shared.Rent((int)Count);
            try
            {
                Span<DxgkAllocation> Allocations = Rented.AsSpan(0, (int)Count);
                NTSTATUS Status = Process.TryResolve(Instance, Device, ListPtr, Allocations);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                foreach (DxgkAllocation Allocation in Allocations)
                {
                    if (Allocation.LockCount == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                foreach (DxgkAllocation Allocation in Allocations)
                {
                    if (Allocation.LockCount != 0)
                        Allocation.LockCount--;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }
            finally
            {
                ArrayPool<DxgkAllocation>.Shared.Return(Rented, clearArray: true);
            }
        }
    }
}
