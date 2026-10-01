using System;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionGetFrameStatistics : IWinSyscall
    {
        private const int FrameStatisticsSize = 0x28;
        private const int FeatureLevelsSize = 0x14;
        private const uint D3DFeatureLevel12_1 = 0xC100;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong StatisticsPtr = Instance.WinHelper.GetArg(0);
            ulong FeatureLevelsPtr = Instance.WinHelper.GetArg(1);

            if (StatisticsPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(StatisticsPtr, FrameStatisticsSize)
                || (FeatureLevelsPtr != 0 && !Instance.IsRegionMapped(FeatureLevelsPtr, FeatureLevelsSize)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            const long Frequency = KuserSharedDataManager.QpcFrequency;
            long Period = Instance.WinHelper.GetDisplayRefreshPeriod();
            long Now = (long)Instance.GetEmulatedPerformanceCounter();
            long LastFrameTime = WinSysHelper.GetLastVerticalBlank(Now, Period);

            // NT reports the rate as frequency over period and the next frame two periods after the last one.
            Span<byte> Statistics = stackalloc byte[FrameStatisticsSize];
            BinaryPrimitives.WriteInt64LittleEndian(Statistics, LastFrameTime);
            BinaryPrimitives.WriteUInt32LittleEndian(Statistics.Slice(0x08), (uint)Frequency);
            BinaryPrimitives.WriteUInt32LittleEndian(Statistics.Slice(0x0C), (uint)Period);
            BinaryPrimitives.WriteInt64LittleEndian(Statistics.Slice(0x10), Now);
            BinaryPrimitives.WriteInt64LittleEndian(Statistics.Slice(0x18), Frequency);
            BinaryPrimitives.WriteInt64LittleEndian(Statistics.Slice(0x20), LastFrameTime + 2 * Period);
            if (!Instance.WriteMemory(StatisticsPtr, Statistics))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (FeatureLevelsPtr != 0)
            {
                Span<byte> FeatureLevels = stackalloc byte[FeatureLevelsSize];
                FeatureLevels.Clear();
                BinaryPrimitives.WriteUInt32LittleEndian(FeatureLevels, D3DFeatureLevel12_1);
                BinaryPrimitives.WriteUInt32LittleEndian(FeatureLevels.Slice(0x04), D3DFeatureLevel12_1);
                if (!Instance.WriteMemory(FeatureLevelsPtr, FeatureLevels))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
