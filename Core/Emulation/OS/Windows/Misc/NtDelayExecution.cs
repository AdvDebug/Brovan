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

        private static bool TryGetYieldTimeAdvanceMs(BinaryEmulator Instance, EmulatedThread CurrentThread, int MaxAdvanceMs, out int AdvanceMs)
        {
            AdvanceMs = 0;

            long Now = Instance.EmulatedTickCount64;
            long BestDelta = long.MaxValue;

            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread == null || Thread == CurrentThread)
                    continue;

                if (Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive || Thread.WaitDeadline == -1)
                    continue;

                long Delta = Thread.WaitDeadline - Now;
                if (Delta <= 0)
                {
                    AdvanceMs = 0;
                    return true;
                }

                if (Delta < BestDelta)
                    BestDelta = Delta;
            }

            if (BestDelta == long.MaxValue)
                return false;

            long Clamped = BestDelta > MaxAdvanceMs ? MaxAdvanceMs : BestDelta;
            AdvanceMs = Clamped < 1 ? 1 : (int)Clamped;
            return true;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            bool Alertable = Instance.WinHelper.GetArg64(0) != 0;
            ulong DelayIntervalPtr = Instance.WinHelper.GetArg64(1);
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
                const int MaxYieldAdvanceMs = 16;
                if (TryGetYieldTimeAdvanceMs(Instance, Thread, MaxYieldAdvanceMs, out int AdvanceMs) && AdvanceMs > 0)
                    Instance.AdvanceEmulatedTimeMilliseconds(AdvanceMs, AdvanceTimestampCounter: true);

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
