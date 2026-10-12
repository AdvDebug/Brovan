using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDelayExecution : IWinSyscall
    {
        private static NTSTATUS ContinueDelay(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            Thread.State = EmulatedThreadState.Waiting;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Alertable = (byte)Instance.WinHelper.GetArg(0) != 0;
            ulong DelayIntervalPtr = Instance.WinHelper.GetArg(1);
            EmulatedThread Thread = Instance.CurrentThread;

            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (WinEmulatedThread.GetState(Thread).WaitCompleted)
            {
                NTSTATUS Status = WinEmulatedThread.GetState(Thread).WaitStatus;
                WinEmulatedThread.GetState(Thread).WaitCompleted = false;
                WinEmulatedThread.GetState(Thread).WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (Thread.WaitActive)
                return ContinueDelay(Instance, Thread);

            // NT only requires 4-byte alignment for the interval.
            if ((DelayIntervalPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (!Instance.IsAccessible(DelayIntervalPtr, sizeof(long), false) || !Instance.WinHelper.TryReadUInt64(DelayIntervalPtr, out ulong CapturedInterval))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            long Interval = unchecked((long)CapturedInterval);
            long DelayMs = Instance.WinHelper.TimeoutToMilliseconds(Interval);

            if (Instance.WinHelper.TryEndWaitWithUserApc(Thread, Alertable))
                return NTSTATUS.STATUS_USER_APC;

            if (DelayMs <= 0)
            {
                // NT returns the yield's status for a zero interval (KeDelayExecutionThread).
                NTSTATUS Status = NtYieldExecution.Yield(Instance, Thread);

                // A zero delay is a yield, so whoever the caller is standing aside for has to be looked at now.
                Instance.WakeSignal.Bump();
                return Interval == 0 ? Status : NTSTATUS.STATUS_SUCCESS;
            }

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip();
            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = Instance.CreateEmulatedDeadlineMilliseconds(DelayMs);
            WinEmulatedThread.GetState(Thread).WaitCompleted = false;
            WinEmulatedThread.GetState(Thread).WaitStatus = NTSTATUS.STATUS_PENDING;
            WinEmulatedThread.GetState(Thread).WaitResumeRIP = SyscallRip;
            WinEmulatedThread.GetState(Thread).WaitReturnRIP = SyscallRip + 2;
            WinEmulatedThread.GetState(Thread).WaitAlertable = Alertable;
            WinEmulatedThread.GetState(Thread).ApcAlertable = Alertable;

            Thread.State = EmulatedThreadState.Waiting;
            Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
