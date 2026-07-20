using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueueApcThreadEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong ReserveHandle = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcArgument1 = Instance.WinHelper.GetArg(3);
            ulong ApcArgument2 = Instance.WinHelper.GetArg(4);
            ulong ApcArgument3 = Instance.WinHelper.GetArg(5);

            uint ApcFlags = 0;
            if (ReserveHandle == 1)
                ApcFlags = WinPendingUserApc.SpecialUserApc;

            EmulatedThread Thread = NtQueueApcThread.GetTargetThread(Instance, ThreadHandle);
            return NtQueueApcThread.Queue(Instance, Thread, ApcFlags, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        }
    }
}