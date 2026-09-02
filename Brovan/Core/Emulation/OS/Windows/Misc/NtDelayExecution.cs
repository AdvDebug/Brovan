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

        private static long ReadDelayMs(BinaryEmulator Instance, ulong Ptr)
        {
            if (Ptr == 0)
                return 0;

            long QuadPart = unchecked((long)Instance._emulator.ReadMemoryULong(Ptr));
            long Delta100Ns;

            if (QuadPart >= 0)
            {
                long NowFileTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
                if (QuadPart <= NowFileTime)
                    return 0;

                Delta100Ns = QuadPart - NowFileTime;
            }
            else
            {
                Delta100Ns = QuadPart == long.MinValue ? long.MaxValue : -QuadPart;
            }

            long DelayMs = Delta100Ns / 10000;
            if ((Delta100Ns % 10000) != 0 && DelayMs < long.MaxValue)
                DelayMs++;

            return DelayMs;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            bool Alertable = (uint)Instance.WinHelper.GetArg(0) != 0;
            ulong DelayIntervalPtr = Instance.WinHelper.GetArg(1);
            long DelayMs = ReadDelayMs(Instance, DelayIntervalPtr);
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

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Thread, false);
            ulong NextRip = SyscallRip + 2;

            if (DelayMs <= 0)
            {
                // A zero delay is a yield, so whoever the caller is standing aside for has to be looked at now.
                Instance.WakeSignal.Bump();
                Instance._emulator.WriteRegister(Instance.IPRegister, NextRip);
                Thread.State = EmulatedThreadState.Ready;
                Instance._emulator.StopEmulation();
                return NTSTATUS.STATUS_SUCCESS;
            }

            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = Instance.CreateEmulatedDeadlineMilliseconds(DelayMs);
            WinEmulatedThread.GetState(Thread).WaitCompleted = false;
            WinEmulatedThread.GetState(Thread).WaitStatus = NTSTATUS.STATUS_PENDING;
            WinEmulatedThread.GetState(Thread).WaitResumeRIP = SyscallRip;
            WinEmulatedThread.GetState(Thread).WaitReturnRIP = NextRip;
            WinEmulatedThread.GetState(Thread).WaitAlertable = Alertable;
            WinEmulatedThread.GetState(Thread).ApcAlertable = Alertable;

            Thread.State = EmulatedThreadState.Waiting;
            Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
