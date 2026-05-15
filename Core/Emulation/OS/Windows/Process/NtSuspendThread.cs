using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSuspendThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong PreviousSuspendCountPtr = Instance.WinHelper.GetArg64(1);

            EmulatedThread TargetThread = null;
            if (ThreadHandle == 0xFFFFFFFFFFFFFFFEUL)
                TargetThread = Instance.CurrentThread;
            else
                TargetThread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);

            if (TargetThread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (PreviousSuspendCountPtr != 0)
            {
                if (!Instance.IsRegionMapped(PreviousSuspendCountPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PreviousSuspendCountPtr, (uint)TargetThread.SuspendCount);
            }

            TargetThread.SuspendCount++;
            TargetThread.State = EmulatedThreadState.Suspended;

            if (Instance.CurrentThread != null && TargetThread.ThreadId == (uint)Instance.CurrentThreadId)
            {
                ulong SyscallRip = Instance.WinHelper.GetSyscallRip(TargetThread, true);
                ulong NextRip = SyscallRip + 2;
                Instance._emulator.WriteRegister(Instance.IPRegister, NextRip);
                Instance._emulator.StopEmulation();
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
