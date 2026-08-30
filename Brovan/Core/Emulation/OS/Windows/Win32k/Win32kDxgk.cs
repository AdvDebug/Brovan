using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    /// <summary>
    /// The single display adapter Brovan presents through D3DKMT. Brovan renders through one BrovVulk device
    /// on every host, so the kernel view of the GPU is synthetic and identical everywhere.
    /// </summary>
    internal static class Win32kDxgk
    {
        internal const uint AdapterHandle = 0x40000001;
        internal const uint LuidLowPart = 0x0000B00F;
        internal const int LuidHighPart = 1;

        internal const uint VidPnSourceCount = 1;

        // A guest that sizes its pools from the kernel view gets the same answer on every host, because the
        // number is not the host GPU's. DXGI reports the real device through BrovVulk.
        internal const ulong DedicatedVideoMemory = 4UL << 30;
        internal const ulong SharedSystemMemory = 4UL << 30;

        internal static bool IsAdapter(uint Handle) => Handle == AdapterHandle;

        internal static bool MatchesLuid(uint LowPart, int HighPart)
            => LowPart == LuidLowPart && HighPart == LuidHighPart;

        internal static void WriteLuid(Span<byte> Destination)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0, 4), LuidLowPart);
            BinaryPrimitives.WriteInt32LittleEndian(Destination.Slice(4, 4), LuidHighPart);
        }

        // D3DKMT_ADAPTERINFO: hAdapter, LUID, NumOfSources, bPrecisePresentRegionsPreferred.
        internal const int AdapterInfoSize = 20;

        internal static void WriteAdapterInfo(Span<byte> Destination)
        {
            Destination.Slice(0, AdapterInfoSize).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(0, 4), AdapterHandle);
            WriteLuid(Destination.Slice(4, 8));
            BinaryPrimitives.WriteUInt32LittleEndian(Destination.Slice(12, 4), VidPnSourceCount);
        }
    }
}
