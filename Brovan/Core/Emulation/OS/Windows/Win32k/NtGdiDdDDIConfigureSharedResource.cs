using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIConfigureSharedResource : IWinSyscall
    {
        private const int OffsetResource = 4;
        private const int OffsetIsDwm = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;
            int OffsetProcess = PointerSize == 8 ? 16 : 12;

            Span<byte> Arguments = stackalloc byte[24];
            Arguments = Arguments.Slice(0, OffsetProcess + PointerSize);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device)
                || !Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetResource)), Device, out DxgkResource Resource)
                || !Resource.Shared)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Brovan's DWM role reaches the resource through the surface that binds it, so nothing is recorded.
            return Arguments[OffsetIsDwm] != 0 ? NTSTATUS.STATUS_SUCCESS : Instance.WinUnimplemented;
        }
    }
}
