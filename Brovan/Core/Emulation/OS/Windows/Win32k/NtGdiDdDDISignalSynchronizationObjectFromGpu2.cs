using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDISignalSynchronizationObjectFromGpu2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetHandles = PointerSize;
            int OffsetFlags = OffsetHandles + PointerSize;
            int OffsetContextCount = OffsetFlags + 4;
            int OffsetContexts = OffsetContextCount + 4;

            // The fence values sit in a union that is 8-byte aligned on both architectures.
            int OffsetValues = PointerSize == 8 ? 32 : 24;

            Span<byte> Arguments = stackalloc byte[40];
            Arguments = Arguments.Slice(0, OffsetValues + PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Arguments);
            uint ContextCount = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetContextCount));
            if (Count == 0 || ContextCount == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (ContextCount != 1 || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags)) != 0)
                return Instance.WinUnimplemented;

            if (!DxgkFence.IsCountBounded(Count))
                return NTSTATUS.STATUS_NO_MEMORY;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            ulong ContextsPtr = WinSysHelper.ReadPointerField(Arguments.Slice(OffsetContexts), 0, (uint)PointerSize);
            if (!Instance.WinHelper.TryReadUInt32(ContextsPtr, out uint ContextHandle) || !Process.TryGet(ContextHandle, out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkFence[] Fences = new DxgkFence[Count];
            NTSTATUS Status = Process.TryResolve(Instance, Context.Device, WinSysHelper.ReadPointerField(Arguments.Slice(OffsetHandles), 0, (uint)PointerSize), Fences.AsSpan());
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong[] Values = new ulong[Count];
            if (!DxgkFence.TryReadValues(Instance, WinSysHelper.ReadPointerField(Arguments.Slice(OffsetValues), 0, (uint)PointerSize), Values))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Context.Device.Faulted)
                return NTSTATUS.STATUS_SUCCESS;

            if (!DxgkFence.IsForward(Fences, Values, CountQueued: true))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Process.Gpu.TryEnqueue(Instance, Context, new DxgkSignalPacket { Fences = Fences, Values = Values }))
                return NTSTATUS.STATUS_NO_MEMORY;

            DxgkFence.RaiseQueuedValues(Fences, Values);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
