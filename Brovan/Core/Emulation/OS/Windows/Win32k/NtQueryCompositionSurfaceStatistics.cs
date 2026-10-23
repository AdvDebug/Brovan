namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtQueryCompositionSurfaceStatistics : IWinSyscall
    {
        // NT: wow64win copies a 32-bit caller's fields one by one and skips the padding between them.
        private static readonly (int Offset, int Size)[] Fields32 = { (0, 20), (24, 12), (40, 20), (64, 12) };

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SurfaceHandle = Instance.WinHelper.GetArg(0);
            ulong StatisticsPtr = Instance.WinHelper.GetArg(1);

            // NT writes the whole block whatever the status.
            Span<byte> Statistics = stackalloc byte[DxgkCompositionSurface.StatisticsSize];
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(SurfaceHandle, AccessMask.CompositionSurfaceQuery, out DxgkCompositionSurface Surface);
            if (Status == NTSTATUS.STATUS_SUCCESS)
            {
                Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                if (Surface.ActiveBuffer is { HasStatistics: true } Active)
                {
                    Active.Statistics.CopyTo(Statistics);
                    Status = NTSTATUS.STATUS_SUCCESS;
                }
            }

            if (StatisticsPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Instance.WinHelper.PointerSize == 8)
            {
                Instance.WriteMemory(StatisticsPtr, Statistics);
            }
            else
            {
                foreach ((int Offset, int Size) in Fields32)
                    Instance.WriteMemory(StatisticsPtr + (ulong)Offset, Statistics.Slice(Offset, Size));
            }

            return Status;
        }
    }
}
