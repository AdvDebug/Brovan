using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDxgkEnumAdapters3 : IWinSyscall
    {
        // D3DKMT_ENUMADAPTERS3 opens with D3DKMT_ENUMADAPTERS_FILTER, a ULONGLONG on both architectures.
        private const ulong OffsetNumAdapters = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            int PointerSize = Instance.WinHelper.PointerSize;
            ulong OffsetAdapters = OffsetNumAdapters + (ulong)PointerSize;

            if (ArgumentsPtr == 0 || !Instance.IsRegionMapped(ArgumentsPtr, OffsetAdapters + (ulong)PointerSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Count = Instance.ReadMemoryUInt(ArgumentsPtr + OffsetNumAdapters);
            ulong AdaptersPtr = Instance.WinHelper.ReadPointer(ArgumentsPtr + OffsetAdapters);

            if (AdaptersPtr == 0)
            {
                Instance._emulator.WriteMemory(ArgumentsPtr + OffsetNumAdapters, 1u, 4);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Count < 1)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (!Instance.IsRegionMapped(AdaptersPtr, NtGdiDdDDIEnumAdapters2.AdapterInfoSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Info = Instance.WinHelper.Shared.GetSpan(NtGdiDdDDIEnumAdapters2.AdapterInfoSize);
            Info.Slice(0, NtGdiDdDDIEnumAdapters2.AdapterInfoSize).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(0, 4), Win32kDxgk.AdapterHandle);
            Win32kDxgk.WriteLuid(Info.Slice(4, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(Info.Slice(12, 4), Win32kDxgk.VidPnSourceCount);

            if (!Instance.WriteMemory(AdaptersPtr, Info.Slice(0, NtGdiDdDDIEnumAdapters2.AdapterInfoSize)))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance._emulator.WriteMemory(ArgumentsPtr + OffsetNumAdapters, 1u, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
