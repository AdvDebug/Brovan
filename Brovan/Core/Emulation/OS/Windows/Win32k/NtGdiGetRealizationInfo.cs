using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetRealizationInfo : IWinSyscall
    {
        // The sizes of FONT_REALIZATION_INFO, its 24-byte form and FONT_REALIZATION_INFO2.
        private const uint RealizationInfoShortSize = 16;
        private const uint RealizationInfoSize = 24;
        private const uint RealizationInfo2Size = 0x32C;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong InfoPtr = Instance.WinHelper.GetArg(1);

            Instance.SetRawSyscallReturn(0);
            if (InfoPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (!Instance.WinHelper.TryReadUInt32(InfoPtr, out uint Size)
                || Size is not (RealizationInfoShortSize or RealizationInfoSize or RealizationInfo2Size))
            {
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Size).Slice(0, (int)Size);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer, Size);

            if (!Instance.WriteMemory(InfoPtr, Buffer))
                return NTSTATUS.STATUS_SUCCESS;

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
