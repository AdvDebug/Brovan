using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDISetContextInProcessSchedulingPriority : IWinSyscall
    {
        internal const int ArgumentsSize = 8;
        internal const int OffsetPriority = 4;
        private const uint HighestPriority = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            Span<byte> Arguments = stackalloc byte[ArgumentsSize];
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Priority = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetPriority));
            if (Priority > HighestPriority || !Instance.WinHelper.DxgkProcess.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Context.Device.Faulted)
                return NTSTATUS.STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE;

            Context.InProcessPriority = Priority;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
