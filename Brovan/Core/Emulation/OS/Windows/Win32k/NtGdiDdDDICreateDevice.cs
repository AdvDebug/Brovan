using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICreateDevice : IWinSyscall
    {
        private const uint FlagLegacyMode = 0x1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            // D3DKMT_CREATEDEVICE opens with a pointer-sized union that holds the adapter.
            int OffsetFlags = Instance.WinHelper.PointerSize;
            int OffsetDevice = OffsetFlags + 4;

            Span<byte> Arguments = stackalloc byte[16];
            Arguments = Arguments.Slice(0, OffsetDevice + 4);
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkAdapter Adapter))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Adapter.Kind != DxgkAdapterKind.BasicRender || (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags)) & FlagLegacyMode) != 0)
                return Instance.WinUnimplemented;

            DxgkDevice Device = new() { Adapter = Adapter };
            if (!Process.TryAdd(Device, out uint Handle))
                return NTSTATUS.STATUS_NO_MEMORY;

            if (Instance.WinHelper.WriteUInt32(ArgumentsPtr + (ulong)OffsetDevice, Handle))
                return NTSTATUS.STATUS_SUCCESS;

            Process.Destroy(Instance, Device);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
