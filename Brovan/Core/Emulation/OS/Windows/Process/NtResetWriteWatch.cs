using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtResetWriteWatch : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) =>
            Instance.WinHelper.ResolveAddressSpaceCall(Instance.WinHelper.GetArg(0), AccessMask.ProcessVMOperation);

        private const ulong PageSize = 0x1000;
        private const ulong HighestUserAddress = NtWow64GetNativeSystemInformation.NativeMaximumUserModeAddress;
        private const ulong UserProbeAddress = NtWow64GetNativeSystemInformation.NativeUserProbeAddress;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddress = Instance.WinHelper.GetArg(1);
            ulong RegionSize = Instance.WinHelper.GetArg(2);

            if (BaseAddress > HighestUserAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            if (UserProbeAddress - BaseAddress < RegionSize || RegionSize == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            NTSTATUS Status = Instance.WinHelper.TakeOrResolveProcess(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Process.PID != Instance.WinHelper.PID)
                return Instance.WinUnimplemented;

            ulong Last = BaseAddress + RegionSize - 1;
            using RankedLock.Scope AddressHold = Instance.AddressSpace.Hold();
            if (!Instance.IsWriteWatchRange(BaseAddress, Last))
                return NTSTATUS.STATUS_INVALID_PARAMETER_1;

            return Instance.ResetWrittenPages(BaseAddress & ~(PageSize - 1), (Last & ~(PageSize - 1)) + PageSize)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_UNSUCCESSFUL;
        }
    }
}
