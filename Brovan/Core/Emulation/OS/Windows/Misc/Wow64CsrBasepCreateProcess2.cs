using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64CsrBasepCreateProcess2 : IWinSyscall
    {
        // The 32-bit BASE_CREATEPROCESS_MSG that wow64base translates.
        private const int OffProcessHandle = 0x00;
        private const int OffSxsFlags = 0x20;
        private const int OffSupportedOs = 0x94;
        private const int OffMaxVersionTested = 0xA0;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Message = Instance.WinHelper.GetArg(0);
            if (Message == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Header = stackalloc byte[OffSxsFlags + 4];
            if (!Instance._emulator.ReadMemory(Message, Header))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint ProcessHandle = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(OffProcessHandle));
            uint SxsFlags = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(OffSxsFlags));
            if (!CsrssPortHandler.TryReadChildCompatibility(Instance, ProcessHandle, SxsFlags, out uint SupportedOs, out ulong MaxVersionTested))
                return NTSTATUS.STATUS_SUCCESS;

            if (!Instance._emulator.WriteMemory(Message + OffSupportedOs, SupportedOs) || !Instance._emulator.WriteMemory(Message + OffMaxVersionTested, MaxVersionTested, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
