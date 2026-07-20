using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtYieldExecution : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Thread, true);
            ulong NextRip = SyscallRip + 2;
            Instance._emulator.WriteRegister(Instance.IPRegister, NextRip);

            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
