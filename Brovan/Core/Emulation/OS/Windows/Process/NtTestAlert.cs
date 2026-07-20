using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTestAlert : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (WinEmulatedThread.GetState(Thread).PendingUserApcs == null || WinEmulatedThread.GetState(Thread).PendingUserApcs.Count == 0)
                return NTSTATUS.STATUS_SUCCESS;

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Thread, true);
            ulong NextRip = SyscallRip + 2;
            Instance._emulator.WriteRegister(Instance.IPRegister, NextRip);
            WinEmulatedThread.GetState(Thread).ApcAlertable = true;
            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}