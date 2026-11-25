using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMsgWaitForMultipleObjectsEx : IWinSyscall
    {
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint MWMO_WAITALL = 0x0001;
        private const uint MWMO_ALERTABLE = 0x0002;
        private const uint MaximumWaitObjects = 64;

        private static bool TryGetSatisfiedIndex(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State, bool WaitAll, uint WakeMask, out NTSTATUS WaitStatus)
        {
            WaitStatus = NTSTATUS.STATUS_SUCCESS;
            bool MessageReady = Win32kHelper.HasQueuedInputEvent(Instance, WakeMask, Thread.ThreadId);

            if (WaitAll)
            {
                if (!Instance.AreWaitObjectsSignaled(Thread, State) || !MessageReady)
                    return false;

                WaitStatus = Instance.TakeAllWaitObjects(Thread, State);
                return true;
            }

            if (Instance.TryTakeAnyWaitObject(Thread, State, out _, out WaitStatus))
                return true;

            if (MessageReady || Win32kQueuePort.TryEndMsgWait(Instance, Thread, State, WakeMask))
            {
                WaitStatus = (NTSTATUS)(uint)State.WaitObjectCount;
                return true;
            }

            return false;
        }

        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread, uint WakeMask)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (TryGetSatisfiedIndex(Instance, Thread, State, Thread.WaitAll, WakeMask, out NTSTATUS WaitStatus))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                return WaitStatus;
            }

            if (Instance.IsEmulatedDeadlineExpired(State.MsgWaitTimeout))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                return NTSTATUS.STATUS_TIMEOUT;
            }

            Thread.WaitDeadline = Win32kHelper.GetMsgWaitDeadline(Instance, Thread.ThreadId, WakeMask, State.MsgWaitTimeout);

            return Instance.WinHelper.ContinueParked(Thread);
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint Count = (uint)Instance.WinHelper.GetArg(0);
            ulong HandlesPtr = Instance.WinHelper.GetArg(1);
            uint MillisecondsTimeout = (uint)Instance.WinHelper.GetArg(2);
            uint WakeMask = (uint)Instance.WinHelper.GetArg(3);
            uint Flags = (uint)Instance.WinHelper.GetArg(4);

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

            ulong HandleSize = (ulong)Instance.WinHelper.PointerSize;

            if (Count > 0 && !Instance.IsRegionMapped(HandlesPtr, Count * HandleSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            State.ClearWaitObjects();
            for (int i = 0; i < Count; i++)
                Instance.AddWaitObject(State, Instance.WinHelper.HandleManager.GetObjectByHandle(Instance.WinHelper.ReadPointer(HandlesPtr + (ulong)i * HandleSize)));

            bool WaitAll = (Flags & MWMO_WAITALL) != 0;
            bool Alertable = (Flags & MWMO_ALERTABLE) != 0;

            // win32k returns a ready message before the APC check, except WAITALL with handles.
            bool MessageFirst = (!WaitAll || Count == 0) && Alertable && State.PendingUserApcs.Count > 0
                && Win32kHelper.HasQueuedInputEvent(Instance, WakeMask, Thread.ThreadId);
            if (!MessageFirst && Instance.WinHelper.TryEndWaitWithUserApc(Thread, Alertable))
            {
                State.ClearWaitObjects();
                return NTSTATUS.STATUS_USER_APC;
            }

            if (TryGetSatisfiedIndex(Instance, Thread, State, WaitAll, WakeMask, out NTSTATUS ImmediateStatus))
            {
                State.ClearWaitObjects();
                return ImmediateStatus;
            }

            long Deadline = MillisecondsTimeout == INFINITE ? -1 : Instance.CreateEmulatedDeadlineMilliseconds(MillisecondsTimeout);
            if (Deadline == Instance.EmulatedTickCount64)
            {
                State.ClearWaitObjects();
                return NTSTATUS.STATUS_TIMEOUT;
            }

            long WaitDeadline = Win32kHelper.GetMsgWaitDeadline(Instance, Thread.ThreadId, WakeMask, Deadline);
            State.MsgWaitActive = true;
            State.MsgWaitMask = WakeMask;
            State.MsgWaitTimeout = Deadline;
            return Instance.WinHelper.ParkUntil(Thread, WaitDeadline, Alertable, OnObjects: true, WaitAll);
        }
    }
}
