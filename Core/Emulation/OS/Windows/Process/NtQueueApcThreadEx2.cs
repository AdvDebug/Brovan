using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueueApcThreadEx2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong ReserveHandle = Instance.WinHelper.GetArg64(1);
            uint ApcFlags = (uint)Instance.WinHelper.GetArg64(2);
            ulong ApcRoutine = Instance.WinHelper.GetArg64(3);
            ulong ApcArgument1 = Instance.WinHelper.GetArg64(4);
            ulong ApcArgument2 = Instance.WinHelper.GetArg64(5);
            ulong ApcArgument3 = Instance.WinHelper.GetArg64(6);

            EmulatedThread Thread = NtQueueApcThread.GetTargetThread(Instance, ThreadHandle);
            return NtQueueApcThread.Queue(Instance, Thread, ApcFlags, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
        }
    }
}