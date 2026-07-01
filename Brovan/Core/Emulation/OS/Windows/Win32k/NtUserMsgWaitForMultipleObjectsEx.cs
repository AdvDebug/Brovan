using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMsgWaitForMultipleObjectsEx : IWinSyscall
    {
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint MWMO_WAITALL = 0x0001;
        private const uint MWMO_ALERTABLE = 0x0002;
        private const uint MaximumWaitObjects = 64;

        private static bool TryGetSatisfiedIndex(BinaryEmulator Instance, EmulatedThread Thread, List<ulong> Handles, bool WaitAll, uint WakeMask, out NTSTATUS WaitStatus)
        {
            WaitStatus = NTSTATUS.STATUS_SUCCESS;
            bool MessageReady = Win32kHelper.HasQueuedInputEvent(Instance, WakeMask);

            if (WaitAll)
            {
                for (int i = 0; i < Handles.Count; i++)
                {
                    if (!Instance.CanSatisfyWaitHandle(Handles[i], Thread))
                        return false;
                }

                if (!MessageReady)
                    return false;

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

                return true;
            }

            for (int i = 0; i < Handles.Count; i++)
            {
                if (!Instance.TryAcquireWaitHandle(Handles[i], Thread, out NTSTATUS AcquiredStatus))
                    continue;

                WaitStatus = AcquiredStatus == NTSTATUS.STATUS_ABANDONED_WAIT_0
                    ? (NTSTATUS)((uint)NTSTATUS.STATUS_ABANDONED_WAIT_0 + (uint)i)
                    : (NTSTATUS)(uint)i;
                return true;
            }

            if (MessageReady)
            {
                WaitStatus = (NTSTATUS)(uint)Handles.Count;
                return true;
            }

            return false;
        }

        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread, uint WakeMask)
        {
            if (TryGetSatisfiedIndex(Instance, Thread, Thread.WaitHandles, Thread.WaitAll, WakeMask, out NTSTATUS WaitStatus))
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
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            uint Count = (uint)Instance.WinHelper.GetArg64(0);
            ulong HandlesPtr = Instance.WinHelper.GetArg64(1);
            uint MillisecondsTimeout = (uint)Instance.WinHelper.GetArg64(2);
            uint WakeMask = (uint)Instance.WinHelper.GetArg64(3);
            uint Flags = (uint)Instance.WinHelper.GetArg64(4, true);

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);

            if (State.WaitCompleted)
            {
                NTSTATUS Status = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (Thread.WaitActive)
                return ContinueWait(Instance, Thread, State.MsgWaitMask);

            if (Count >= MaximumWaitObjects)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Count > 0 && HandlesPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Count > 0 && !Instance.IsRegionMapped(HandlesPtr, Count * 8UL))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            List<ulong> Handles = new List<ulong>((int)Count);
            for (int i = 0; i < Count; i++)
            {
                ulong H = Instance.ReadMemoryULong(HandlesPtr + (ulong)(i * 8));
                Handles.Add(H);
            }

            bool WaitAll = (Flags & MWMO_WAITALL) != 0;
            bool Alertable = (Flags & MWMO_ALERTABLE) != 0;

            if (TryGetSatisfiedIndex(Instance, Thread, Handles, WaitAll, WakeMask, out NTSTATUS ImmediateStatus))
                return ImmediateStatus;

            long Deadline = MillisecondsTimeout == INFINITE ? -1 : Instance.CreateEmulatedDeadlineMilliseconds(MillisecondsTimeout);
            if (Deadline == Instance.EmulatedTickCount64)
                return NTSTATUS.STATUS_TIMEOUT;

            Thread.WaitActive = true;
            Thread.WaitHandles = Handles;
            Thread.WaitAll = WaitAll;
            Thread.WaitDeadline = Deadline;
            State.MsgWaitActive = true;
            State.MsgWaitMask = WakeMask;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
            State.WaitReturnRIP = State.WaitResumeRIP + 2;
            State.WaitAlertable = Alertable;

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = Alertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_PENDING;
        }
    }
}
