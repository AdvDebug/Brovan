using System.Buffers;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIWaitForSynchronizationObjectFromCpu : IWinSyscall
    {
        private const int OffsetCount = 4;
        private const int OffsetHandles = 8;

        private const uint FlagWaitAny = 0x1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetValues = OffsetHandles + PointerSize;
            int OffsetEvent = OffsetValues + PointerSize;
            int OffsetFlags = OffsetEvent + PointerSize;

            Span<byte> Arguments = stackalloc byte[36];
            Arguments = Arguments.Slice(0, OffsetFlags + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetCount));
            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags));
            if (Count == 0 || (Flags & ~FlagWaitAny) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!DxgkFence.IsCountBounded(Count))
                return NTSTATUS.STATUS_NO_MEMORY;

            ulong HandlesPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetHandles), 0, (uint)PointerSize);
            ulong ValuesPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetValues), 0, (uint)PointerSize);
            ulong EventHandle = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetEvent), 0, (uint)PointerSize);
            DxgkFence[] RentedFences = ArrayPool<DxgkFence>.Shared.Rent((int)Count);
            ulong[] RentedValues = ArrayPool<ulong>.Shared.Rent((int)Count);
            try
            {
                Span<DxgkFence> Fences = RentedFences.AsSpan(0, (int)Count);
                Span<ulong> Values = RentedValues.AsSpan(0, (int)Count);
                if (!DxgkFence.TryReadValues(Instance, ValuesPtr, Values))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                DxgkProcess Process = Instance.WinHelper.DxgkProcess;
                if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                WinEvent Event = null;
                if (EventHandle != 0)
                {
                    NTSTATUS Referenced = Instance.WinHelper.ReferenceObjectByHandle(EventHandle, AccessMask.EventModifyState, out Event);
                    if (Referenced != NTSTATUS.STATUS_SUCCESS)
                        return Referenced;
                }

                NTSTATUS Status = Process.TryResolve(Instance, Device, HandlesPtr, Fences);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;

                bool WaitAny = (Flags & FlagWaitAny) != 0;
                if (DxgkFenceWaiter.AreSatisfied(Fences, Values, WaitAny))
                {
                    if (Event != null)
                        Event.Signaled = true;
                    return NTSTATUS.STATUS_SUCCESS;
                }

                DxgkFenceWaiter Waiter = new() { Fences = Fences.ToArray(), Values = Values.ToArray(), WaitAny = WaitAny, Event = Event };
                if (Event != null)
                    return Waiter.TryRegister(Process) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NO_MEMORY;

                Waiter.Request = new DxgkFenceWait();
                if (!Waiter.TryRegister(Process))
                    return NTSTATUS.STATUS_NO_MEMORY;

                Instance.WinHelper.ParkForIoRequest(Waiter.Request);
                return NTSTATUS.STATUS_PENDING;
            }
            finally
            {
                ArrayPool<DxgkFence>.Shared.Return(RentedFences, clearArray: true);
                ArrayPool<ulong>.Shared.Return(RentedValues);
            }
        }
    }
}
