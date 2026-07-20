using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlertMultipleThreadByThreadId : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadIds = Instance.WinHelper.GetArg(0);
            uint Count = (uint)Instance.WinHelper.GetArg(1);
            _ = Instance.WinHelper.GetArg(2);
            _ = Instance.WinHelper.GetArg(3);

            if (Count == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (ThreadIds == 0 || !Instance.IsRegionMapped(ThreadIds, Count * 8UL))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS FirstFailure = NTSTATUS.STATUS_SUCCESS;
            for (uint Index = 0; Index < Count; Index++)
            {
                uint ThreadId = (uint)Instance.ReadMemoryULong(ThreadIds + Index * 8UL);
                NTSTATUS Status = NtAlertThreadByThreadId.AlertThread(Instance, ThreadId);
                if (Status != NTSTATUS.STATUS_SUCCESS && FirstFailure == NTSTATUS.STATUS_SUCCESS)
                    FirstFailure = Status;
            }

            return FirstFailure;
        }
    }
}
