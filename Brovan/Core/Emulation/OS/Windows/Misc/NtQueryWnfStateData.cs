namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryWnfStateData : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong StateNamePtr = Instance.WinHelper.GetArg(0);
            ulong ExplicitScope = Instance.WinHelper.GetArg(2);
            ulong ChangeStampPtr = Instance.WinHelper.GetArg(3);
            ulong Buffer = Instance.WinHelper.GetArg(4);
            ulong BufferSizePtr = Instance.WinHelper.GetArg(5);

            if (!Instance.WinHelper.TryReadUInt64(StateNamePtr, out ulong StateName))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!WnfStateNames.IsValidName(StateName))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsMemoryRangeMapped(ChangeStampPtr, sizeof(uint))
                || !Instance.WinHelper.TryReadUInt32(BufferSizePtr, out uint BufferSize)
                || !Instance.IsMemoryRangeMapped(Buffer, BufferSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT takes an explicit scope only for session, user and process names.
            if (ExplicitScope != 0 && WnfStateNames.GetScope(StateName) is WnfStateNames.DataScope.System
                or WnfStateNames.DataScope.Machine or WnfStateNames.DataScope.PhysicalMachine)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // No WNF state data is kept, so every name reads as one that nothing published.
            if (!Instance.WinHelper.WriteUInt32(ChangeStampPtr, 0) || !Instance.WinHelper.WriteUInt32(BufferSizePtr, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
