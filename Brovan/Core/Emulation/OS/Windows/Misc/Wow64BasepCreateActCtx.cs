using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64BasepCreateActCtx : IWinSyscall
    {
        private const uint OffOutputPointer = 0x7C;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Message = Instance.WinHelper.GetArg(0);

            if (Message == 0 || !Instance.IsRegionMapped(Message, OffOutputPointer + 4))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong OutputPointer = Instance.ReadMemoryUInt(Message + OffOutputPointer);
            if (OutputPointer == 0 || !Instance.IsRegionMapped(OutputPointer, 4))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong ActivationContextData = CsrssPortHandler.AllocActivationContextData(Instance);
            if (ActivationContextData == 0)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (!Instance.WinHelper.WriteUInt32(OutputPointer, (uint)ActivationContextData))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
