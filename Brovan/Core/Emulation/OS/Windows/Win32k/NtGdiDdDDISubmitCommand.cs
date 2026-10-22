using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDISubmitCommand : IWinSyscall
    {
        private const int OffsetFlags = 12;
        private const int OffsetContextCount = 24;
        private const int OffsetContexts = 28;
        private const uint MaxBroadcastContexts = 64;

        // The checks follow WarpKMValidateSubmitCommand and WarpKMSubmitCommandVirtual.
        private const uint WarpSyncSize = 304;
        private const uint WarpIndexedSize = 280;
        private const int WarpZeroPrefix = 256;
        private const int OffsetStartEvent = 288;
        private const int OffsetFinishEvent = 296;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;

            // pPrivateDriverData follows BroadcastContext[64] on the guest pointer alignment.
            int OffsetPrivate = PointerSize == 8 ? 288 : 284;
            int OffsetPrivateSize = OffsetPrivate + PointerSize;
            int OffsetPrimaries = OffsetPrivateSize + 4;
            int OffsetHistory = OffsetPrimaries + 4 + 64;

            Span<byte> Arguments = stackalloc byte[372];
            Arguments = Arguments.Slice(0, OffsetHistory + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint ContextCount = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetContextCount));
            if (ContextCount == 0 || ContextCount > MaxBroadcastContexts)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetContexts)), out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (ContextCount != 1 || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags)) != 0
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetPrimaries)) != 0
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetHistory)) != 0)
                return Instance.WinUnimplemented;

            uint PrivateSize = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetPrivateSize));
            if (PrivateSize > DxgkContext.DmaBufferPrivateDataSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Private = stackalloc byte[(int)DxgkContext.DmaBufferPrivateDataSize];
            Private = Private.Slice(0, (int)PrivateSize);
            if (PrivateSize != 0 && !Instance.ReadMemory(WinSysHelper.ReadPointerField(Arguments.Slice(OffsetPrivate), 0, (uint)PointerSize), Private))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((PrivateSize != WarpSyncSize && PrivateSize != WarpIndexedSize) || Private.Slice(0, WarpZeroPrefix).IndexOfAnyExcept((byte)0) >= 0)
                return NTSTATUS.STATUS_INVALID_USER_BUFFER;

            DxgkDevice Device = Context.Device;
            if (Device.Faulted)
                return NTSTATUS.STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE;

            // NT succeeds a submit that Basic Render cannot build and faults the device, which every 280-byte submit does here.
            if (!Context.DmaBufferReady || PrivateSize == WarpIndexedSize
                || !TryReferenceEvent(Instance, Private, OffsetStartEvent, out WinEvent Start)
                || !TryReferenceEvent(Instance, Private, OffsetFinishEvent, out WinEvent Finish))
            {
                Device.Fault(Instance, Process);
                return NTSTATUS.STATUS_SUCCESS;
            }

            return Process.Gpu.TryEnqueue(Instance, Context, new DxgkSubmitPacket { Start = Start, Finish = Finish })
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_NO_MEMORY;
        }

        // The SYNC block keeps 64-bit handles for a 32-bit caller too.
        private static bool TryReferenceEvent(BinaryEmulator Instance, ReadOnlySpan<byte> Private, int Offset, out WinEvent Event)
        {
            Event = null;
            ulong Handle = BinaryPrimitives.ReadUInt64LittleEndian(Private.Slice(Offset));
            return Handle == 0 || Instance.WinHelper.ReferenceObjectByHandle(Handle, AccessMask.EventModifyState, out Event) == NTSTATUS.STATUS_SUCCESS;
        }
    }
}
