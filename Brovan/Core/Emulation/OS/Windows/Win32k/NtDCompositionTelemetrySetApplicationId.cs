using System;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionTelemetrySetApplicationId : IWinSyscall
    {
        private const int MaxTextBytes = 0x12C;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            ulong TextBytes = Instance.WinHelper.GetArg(1);
            ulong TextPtr = Instance.WinHelper.GetArg(2);

            if (TextPtr == 0 || TextBytes == 0 || (TextBytes & 1) != 0 || TextBytes > MaxTextBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT copies the text before it looks up the channel, and only compositor telemetry reads it.
            Span<byte> Text = stackalloc byte[MaxTextBytes];
            if (!Instance.ReadMemory(TextPtr, Text.Slice(0, (int)TextBytes)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Instance.WinHelper.Composition.Reference(ChannelId, out _);
        }
    }
}
