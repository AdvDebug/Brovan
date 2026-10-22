using System.Buffers;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDISignalSynchronizationObjectFromCpu : IWinSyscall
    {
        private const int OffsetCount = 4;
        private const int OffsetHandles = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetValues = OffsetHandles + PointerSize;
            int OffsetFlags = OffsetValues + PointerSize;

            Span<byte> Arguments = stackalloc byte[28];
            Arguments = Arguments.Slice(0, OffsetFlags + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetCount));
            if (Count == 0 || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!DxgkFence.IsCountBounded(Count))
                return NTSTATUS.STATUS_NO_MEMORY;

            if (!Instance.WinHelper.DxgkProcess.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong HandlesPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetHandles), 0, (uint)PointerSize);
            ulong ValuesPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetValues), 0, (uint)PointerSize);
            DxgkFence[] RentedFences = ArrayPool<DxgkFence>.Shared.Rent((int)Count);
            ulong[] RentedValues = ArrayPool<ulong>.Shared.Rent((int)Count);
            try
            {
                Span<DxgkFence> Fences = RentedFences.AsSpan(0, (int)Count);
                Span<ulong> Values = RentedValues.AsSpan(0, (int)Count);
                NTSTATUS Status = Instance.WinHelper.DxgkProcess.TryResolve(Instance, Device, HandlesPtr, Fences);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                if (!DxgkFence.TryReadValues(Instance, ValuesPtr, Values))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (Device.Faulted)
                    return NTSTATUS.STATUS_SUCCESS;

                if (!DxgkFence.IsForward(Fences, Values, CountQueued: false))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                for (int Index = 0; Index < Fences.Length; Index++)
                    Fences[Index].Signal(Instance, Values[Index]);

                DxgkFence.RaiseQueuedValues(Fences, Values);
                return NTSTATUS.STATUS_SUCCESS;
            }
            finally
            {
                ArrayPool<DxgkFence>.Shared.Return(RentedFences, clearArray: true);
                ArrayPool<ulong>.Shared.Return(RentedValues);
            }
        }
    }
}
