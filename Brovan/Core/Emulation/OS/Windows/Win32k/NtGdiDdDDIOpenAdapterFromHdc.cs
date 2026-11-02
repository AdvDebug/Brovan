using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIOpenAdapterFromHdc : IWinSyscall
    {
        // D3DKMT_OPENADAPTERFROMHDC outputs follow hDc.
        private const int OutputSize = 16;
        private const int OffsetLuid = 4;

        // NT zeroes outputs even when the DC has no adapter.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            if (ArgumentsPtr == 0 || !Instance.WinHelper.TryReadPointer(ArgumentsPtr, out ulong Hdc))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Output = stackalloc byte[OutputSize];

            NTSTATUS Status = NTSTATUS.STATUS_INVALID_PARAMETER;
            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            uint Handle = 0;

            if (Instance.WinHelper.GetDcAttributeAddress(Hdc) != 0)
            {
                if (!Process.TryAdd(Win32kDxgk.Display, out Handle))
                    return NTSTATUS.STATUS_NO_MEMORY;

                BinaryPrimitives.WriteUInt32LittleEndian(Output, Handle);
                Win32kDxgk.WriteLuid(Output.Slice(OffsetLuid, 8), Win32kDxgk.Display);
                Status = NTSTATUS.STATUS_SUCCESS;
            }

            if (Instance.WriteMemory(ArgumentsPtr + (ulong)Instance.WinHelper.PointerSize, Output))
                return Status;

            if (Handle != 0)
                Process.TryRemove<DxgkAdapter>(Handle);

            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
