using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICreateSynchronizationObject : IWinSyscall
    {
        private const int OffsetType = 8;
        private const int OffsetFlags = 12;
        private const int OffsetInitialValue = 16;
        private const int OffsetCpuAddress = 24;
        private const int OffsetGpuAddress = 32;
        private const int OffsetSyncObject = 88;
        private const int ArgumentsSize = 92;

        private const uint TypeMonitoredFence = 5;

        private const uint FlagShared = 0x1;
        private const uint FlagNtSecuritySharing = 0x2;
        private const uint FlagNoGpuAccess = 0x80;
        private const uint FlagReserved0 = 0x80000000;
        private const uint SupportedFlags = FlagShared | FlagNtSecuritySharing | FlagNoGpuAccess | FlagReserved0;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            int PointerSize = Instance.WinHelper.PointerSize;

            Span<byte> Arguments = stackalloc byte[ArgumentsSize];
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkDevice Device))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Flags = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetFlags));
            uint Sharing = Flags & (FlagShared | FlagNtSecuritySharing);
            if (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetType)) != TypeMonitoredFence || (Flags & ~SupportedFlags) != 0
                || Sharing == FlagNtSecuritySharing)
                return Instance.WinUnimplemented;

            if (Sharing == FlagShared)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = DxgkFence.TryCreate(Instance, Process, Device, BinaryPrimitives.ReadUInt64LittleEndian(Arguments.Slice(OffsetInitialValue)), out DxgkFence Fence);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Fence.NtSecuritySharing = Sharing != 0;

            WinSysHelper.WritePointerField(Arguments.Slice(OffsetCpuAddress), 0, (uint)PointerSize, Fence.CpuAddress);
            BinaryPrimitives.WriteUInt64LittleEndian(Arguments.Slice(OffsetGpuAddress), 0);
            if (Instance.WriteMemory(ArgumentsPtr + OffsetCpuAddress, Arguments.Slice(OffsetCpuAddress, OffsetGpuAddress + 8 - OffsetCpuAddress))
                && Instance.WinHelper.WriteUInt32(ArgumentsPtr + OffsetSyncObject, Fence.Handle))
                return NTSTATUS.STATUS_SUCCESS;

            Process.Destroy(Instance, Fence);
            return NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
