using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIQueryVideoMemoryInfo : IWinSyscall
    {
        // hProcess leads the structure and is a HANDLE, so hAdapter and the segment group sit after it.
        private const int OffsetBudget = 16;
        private const int ResultSize = 32;

        private const uint SegmentGroupLocal = 0;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            int OffsetAdapter = Instance.WinHelper.PointerSize;
            Span<byte> Arguments = stackalloc byte[OffsetBudget];
            if (ArgumentsPtr == 0 || !Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.DxgkProcess.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetAdapter)), out DxgkAdapter Adapter))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool Local = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetAdapter + 4)) == SegmentGroupLocal;

            // NT: an adapter with no memory of its own reports the shared segment as its local group.
            bool Dedicated = Adapter.DedicatedVideoMemory != 0;
            ulong Budget = Local
                ? (Dedicated ? Adapter.DedicatedVideoMemory : Win32kDxgk.SharedSegmentSize)
                : (Dedicated ? Win32kDxgk.SharedSegmentSize : 0);

            // Budget, CurrentUsage, CurrentReservation, AvailableForReservation.
            Span<byte> Result = stackalloc byte[ResultSize];
            BinaryPrimitives.WriteUInt64LittleEndian(Result, Budget);
            BinaryPrimitives.WriteUInt64LittleEndian(Result.Slice(24), Budget / 2);
            return Instance.WriteMemory(ArgumentsPtr + OffsetBudget, Result) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
