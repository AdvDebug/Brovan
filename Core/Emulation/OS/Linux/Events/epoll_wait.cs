using System;
using System.Collections.Generic;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal class Epoll_wait : ILinuxSyscall
    {
        private const int EpollEventSize = 12;
        private readonly bool _pwait;

        public Epoll_wait(bool pwait = false)
        {
            _pwait = pwait;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong epfd = Context.Arg0;
            ulong events = Context.Arg1;
            int maxevents = unchecked((int)Context.Arg2);
            int timeout = unchecked((int)Context.Arg3);
            ulong sigmask = _pwait ? Context.Arg4 : 0;
            ulong sigsetsize = _pwait ? Context.Arg5 : 0;

            FileDescriptorEntry? EpollEntry = Helper.DescriptorTable.GetEntry(epfd);
            if (EpollEntry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (EpollEntry.Object is not EpollObject Epoll)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (maxevents <= 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong EventBytes = checked((ulong)maxevents * EpollEventSize);
            if (!Instance.IsRegionMapped(events, EventBytes))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            LinuxThreadState ThreadState = LinuxSignalHelpers.GetOrCreateThreadState(Instance, Helper);
            byte[] SavedSignalMask = null;
            if (!TryApplyTemporarySignalMask(Instance, Helper, Context, ThreadState, sigmask, sigsetsize, out SavedSignalMask))
                return;

            int ReadyCount = LinuxEventHelpers.WriteReadyEvents(Instance, Helper, Epoll, events, maxevents);
            if (ReadyCount < 0)
            {
                RestoreTemporarySignalMask(ThreadState, SavedSignalMask);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (ReadyCount != 0 || timeout == 0)
            {
                RestoreTemporarySignalMask(ThreadState, SavedSignalMask);
                Helper.SetReturnValue(Instance, Context, ReadyCount);
                return;
            }

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null || ThreadState == null)
            {
                RestoreTemporarySignalMask(ThreadState, SavedSignalMask);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ThreadState.EpollWaitActive = true;
            ThreadState.EpollWaitDescriptor = epfd;
            ThreadState.EpollWaitEventsAddress = events;
            ThreadState.EpollWaitMaxEvents = maxevents;
            ThreadState.EpollWaitReturnRIP = LinuxGuest.GetCurrentSyscallReturnAddress(Instance, Context);
            ThreadState.EpollWaitSavedSignalMask = SavedSignalMask;

            if (LinuxSignalHelpers.TryActivatePendingSignal(ThreadState))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINTR);
                Instance._emulator.WriteRegister(Instance.IPRegister, LinuxGuest.GetCurrentSyscallInstructionAddress(Instance, Context));
                Instance._emulator.StopEmulation();
                return;
            }

            long Deadline = GetWaitDeadline(Instance, Helper, Epoll, timeout);
            Thread.WaitActive = true;
            Thread.WaitHandles = new List<ulong> { epfd };
            Thread.WaitAll = false;
            Thread.WaitDeadline = Deadline;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            Thread.State = EmulatedThreadState.Waiting;
            Helper.SetReturnValue(Instance, Context, 0L);
            Instance._emulator.WriteRegister(Instance.IPRegister, LinuxGuest.GetCurrentSyscallInstructionAddress(Instance, Context));
            Instance._emulator.StopEmulation();
        }

        private static bool TryApplyTemporarySignalMask(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, LinuxThreadState State, ulong sigmask, ulong sigsetsize, out byte[] SavedSignalMask)
        {
            SavedSignalMask = null;
            if (sigmask == 0)
                return true;

            if (sigsetsize != LinuxThreadState.SignalSetSize)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return false;
            }

            if (!Instance.IsRegionMapped(sigmask, sigsetsize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            if (State == null)
                return true;

            State.EnsureSignalState();
            SavedSignalMask = (byte[])State.SignalMask.Clone();
            if (!Instance.ReadMemory(sigmask, State.SignalMask.AsSpan(0, LinuxThreadState.SignalSetSize)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            LinuxSignalHelpers.ClearUnblockableSignals(State.SignalMask);
            return true;
        }

        private static void RestoreTemporarySignalMask(LinuxThreadState State, byte[] SavedSignalMask)
        {
            if (State == null || SavedSignalMask == null)
                return;

            Array.Clear(State.SignalMask, 0, State.SignalMask.Length);
            Buffer.BlockCopy(SavedSignalMask, 0, State.SignalMask, 0, Math.Min(State.SignalMask.Length, SavedSignalMask.Length));
            LinuxSignalHelpers.ClearUnblockableSignals(State.SignalMask);
            LinuxSignalHelpers.TryActivatePendingSignal(State);
        }

        private static long GetWaitDeadline(BinaryEmulator Instance, LinuxSyscallsHelper Helper, EpollObject Epoll, int timeout)
        {
            long Deadline = timeout < 0 ? -1 : Instance.CreateEmulatedDeadlineMilliseconds(timeout);
            long TimerDelay = LinuxEventHelpers.GetNextEpollWakeDelayMilliseconds(Helper, Epoll);
            if (TimerDelay < 0)
                return Deadline;

            long TimerDeadline = Instance.CreateEmulatedDeadlineMilliseconds(TimerDelay);
            if (Deadline == -1 || TimerDeadline < Deadline)
                return TimerDeadline;

            return Deadline;
        }
    }
}
