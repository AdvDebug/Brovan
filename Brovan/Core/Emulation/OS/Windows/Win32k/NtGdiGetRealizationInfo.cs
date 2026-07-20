using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetRealizationInfo : IWinSyscall
    {
        private const int RealizationInfoShortSize = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong InfoPtr = Instance.WinHelper.GetArg(1);

            if (InfoPtr == 0 || !Instance.IsRegionMapped(InfoPtr, RealizationInfoShortSize))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RealizationInfoShortSize);
            if (!Instance.ReadMemory(InfoPtr, Buffer.Slice(0, RealizationInfoShortSize), (uint)RealizationInfoShortSize))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int SizeField = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0, 4));
            if (SizeField <= 0 || SizeField > RealizationInfoShortSize)
                SizeField = RealizationInfoShortSize;

            Buffer.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0, 4), SizeField);

            if (!Instance.WriteMemory(InfoPtr, Buffer.Slice(0, RealizationInfoShortSize)))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
