using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtContinueEx : IWinSyscall
    {
        private const uint CONTINUE_FLAG_RAISE_ALERT = 0x1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ContextPtr = Instance.WinHelper.GetArg(0);
            ulong ContinueArgument = Instance.WinHelper.GetArg(1);

            NTSTATUS Status = GetTestAlert(Instance, ContinueArgument, out bool TestAlert);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return NtContinue.Continue(Instance, ContextPtr, TestAlert);
        }

        private static NTSTATUS GetTestAlert(BinaryEmulator Instance, ulong ContinueArgument, out bool TestAlert)
        {
            TestAlert = false;

            if (ContinueArgument == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (ContinueArgument == 1)
            {
                TestAlert = true;
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(ContinueArgument, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint ContinueFlags = (uint)Instance.ReadMemoryULong(ContinueArgument + 4);
            TestAlert = (ContinueFlags & CONTINUE_FLAG_RAISE_ALERT) != 0;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
