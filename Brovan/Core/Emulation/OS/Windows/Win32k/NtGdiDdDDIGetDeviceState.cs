using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIGetDeviceState : IWinSyscall
    {
        private const int OffsetType = 4;
        private const int OffsetState = 8;
        private const uint TypeReset = 3;
        private const uint TypeLast = 6;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            Span<byte> Arguments = stackalloc byte[OffsetState];
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT: the reset state does not look the device up.
            uint Type = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetType));
            if (Type == TypeReset)
                return Instance.WinHelper.WriteUInt32(ArgumentsPtr + OffsetState, 0) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.DxgkProcess.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice _) || Type == 0 || Type > TypeLast)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance.WinUnimplemented;
        }
    }
}
