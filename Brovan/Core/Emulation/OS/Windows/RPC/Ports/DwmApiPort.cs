using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.RPC.Ports
{
    // DwmFlush returns after the next composition pass, at the next vertical blank.
    public static class DwmApiPortHandler
    {
        public static readonly string PortName = CsrssPortHandler.SessionWindowsDirectory + "\\DwmApiPort";

        private const int OffsetRequest = 0x28;
        private const int OffsetResult = 0x2C;
        private const uint RequestFlush = 0x8000000A;

        public static bool TryHandle(string? Port, byte[] SendData, PortReply Reply, BinaryEmulator Instance)
        {
            if (!string.Equals(Port, PortName, StringComparison.OrdinalIgnoreCase) || SendData.Length < OffsetResult + 4)
                return false;

            if (BinaryPrimitives.ReadUInt32LittleEndian(SendData.AsSpan(OffsetRequest)) != RequestFlush)
                return false;

            byte[] Data = (byte[])SendData.Clone();
            BinaryPrimitives.WriteInt32LittleEndian(Data.AsSpan(OffsetResult), 0);
            Reply.Data = Data;
            Reply.NotBeforeTick = Instance.WinHelper.GetNextVerticalBlankTick();
            return true;
        }
    }
}
