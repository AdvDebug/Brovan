using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForMultipleObjects : IWinSyscall
    {
        private static bool TryGetSatisfiedIndex(BinaryEmulator Instance, EmulatedThread Thread, List<ulong> Handles, bool WaitAll, out int Index, out NTSTATUS WaitStatus)
        {
            Index = -1;
            WaitStatus = NTSTATUS.STATUS_SUCCESS;
            if (Handles == null || Handles.Count == 0)
                return false;

            if (WaitAll)
            {
                for (int i = 0; i < Handles.Count; i++)
                {
                    if (!Instance.CanSatisfyWaitHandle(Handles[i], Thread))
                        return false;
                }

                HashSet<ulong> AcquiredHandles = new HashSet<ulong>();
                for (int i = 0; i < Handles.Count; i++)
                {
                    ulong Handle = Handles[i];
                    if (!AcquiredHandles.Add(Handle))
                        continue;

                    if (!Instance.TryAcquireWaitHandle(Handle, Thread, out NTSTATUS AcquiredStatus))
                        return false;

                    if (AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0 && WaitStatus == NTSTATUS.STATUS_SUCCESS)
                        WaitStatus = (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i);
                }

                Index = 0;
                return true;
            }

            for (int i = 0; i < Handles.Count; i++)
            {
                if (!Instance.TryAcquireWaitHandle(Handles[i], Thread, out NTSTATUS AcquiredStatus))
                    continue;

                Index = i;
                WaitStatus = AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0
                    ? (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i)
                    : (NTSTATUS)(uint)i;
                return true;
            }

            return false;
        }

        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (TryGetSatisfiedIndex(Instance, Thread, Thread.WaitHandles, Thread.WaitAll, out int Index, out NTSTATUS WaitStatus))
            {
                Instance.WinHelper.ClearWaitState(Thread);

                return WaitStatus;
            }

            if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                return NTSTATUS.STATUS_TIMEOUT;
            }

            Thread.State = EmulatedThreadState.Waiting;
            WinEmulatedThread.GetState(Thread).ApcAlertable = WinEmulatedThread.GetState(Thread).WaitAlertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint Count = (uint)Instance.WinHelper.GetArg(0);
            ulong HandlesPtr = Instance.WinHelper.GetArg(1);
            uint WaitType = (uint)Instance.WinHelper.GetArg(2);
            bool Alertable = (uint)Instance.WinHelper.GetArg(3) != 0;
            ulong TimeoutPtr = Instance.WinHelper.GetArg(4);

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
                return ContinueWait(Instance, Thread);

            if (Count == 0 || Count > 64)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (HandlesPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint HandleSize = (uint)Instance.WinHelper.PointerSize;

            if (!Instance.IsRegionMapped(HandlesPtr, Count * HandleSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            List<ulong> Handles = new List<ulong>((int)Count);
            for (int i = 0; i < Count; i++)
            {
                ulong H = Instance.WinHelper.ReadPointer(HandlesPtr + (ulong)i * HandleSize);
                Handles.Add(H);
            }

            bool WaitAll = WaitType == 0;
            if (TryGetSatisfiedIndex(Instance, Thread, Handles, WaitAll, out int Index, out NTSTATUS WaitStatus))
                return WaitStatus;

            long Deadline = Instance.WinHelper.ParseRelativeDeadlineMs(TimeoutPtr);
            if (Deadline == Instance.EmulatedTickCount64)
                return NTSTATUS.STATUS_TIMEOUT;

            Thread.WaitActive = true;
            Thread.WaitHandles = Handles;
            Thread.WaitAll = WaitAll;
            Thread.WaitDeadline = Deadline;
            WinEmulatedThread.GetState(Thread).WaitCompleted = false;
            WinEmulatedThread.GetState(Thread).WaitStatus = NTSTATUS.STATUS_PENDING;
            WinEmulatedThread.GetState(Thread).WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
            WinEmulatedThread.GetState(Thread).WaitReturnRIP = WinEmulatedThread.GetState(Thread).WaitResumeRIP + 2;
            WinEmulatedThread.GetState(Thread).WaitAlertable = Alertable;

            Thread.State = EmulatedThreadState.Waiting;
            WinEmulatedThread.GetState(Thread).ApcAlertable = Alertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, WinEmulatedThread.GetState(Thread).WaitResumeRIP);
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_PENDING;
        }
    }
}
