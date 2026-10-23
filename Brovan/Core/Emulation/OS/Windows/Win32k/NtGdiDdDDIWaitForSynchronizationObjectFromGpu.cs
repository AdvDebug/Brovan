using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIWaitForSynchronizationObjectFromGpu : IWinSyscall
    {
        private const int OffsetCount = 4;
        private const int OffsetHandles = 8;

        // The fence values sit in a union that is 8-byte aligned on both architectures.
        private const int OffsetValues = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;

            Span<byte> Arguments = stackalloc byte[OffsetValues + 8];
            Arguments = Arguments.Slice(0, OffsetValues + PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Count = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetCount));
            if (Count == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!DxgkFence.IsCountBounded(Count))
                return NTSTATUS.STATUS_NO_MEMORY;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = DxgkFence.TryReadGpuArguments(Instance, Process, Context.Device,
                WinSysHelper.ReadPointerField(Arguments.Slice(OffsetHandles), 0, (uint)PointerSize),
                WinSysHelper.ReadPointerField(Arguments.Slice(OffsetValues), 0, (uint)PointerSize), Count, out DxgkFence[] Fences, out ulong[] Values);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return Process.Gpu.TryEnqueue(Instance, Context, new DxgkWaitPacket { Fences = Fences, Values = Values })
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_NO_MEMORY;
        }
    }
}
