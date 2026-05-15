using System;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Rt_sigsuspend : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong unewset = Context.Arg0;
            ulong sigsetsize = Context.Arg1;

            if (!LinuxSignalHelpers.IsValidSignalSetSize(sigsetsize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (unewset == 0 || !Instance.IsRegionMapped(unewset, sigsetsize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            LinuxThreadState State = LinuxSignalHelpers.GetOrCreateThreadState(Instance, Helper);
            EmulatedThread Thread = Instance.CurrentThread;
            if (State == null || Thread == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            byte[] PreviousMask = (byte[])State.SignalMask.Clone();
            byte[] TemporaryMask = Instance.ReadMemory(unewset, (uint)sigsetsize);
            LinuxSignalHelpers.ClearUnblockableSignals(TemporaryMask);
            Array.Clear(State.SignalMask, 0, State.SignalMask.Length);
            Buffer.BlockCopy(TemporaryMask, 0, State.SignalMask, 0, (int)sigsetsize);

            State.SigsuspendActive = true;
            State.SigsuspendSavedSignalMask = PreviousMask;
            State.SigsuspendReturnRIP = LinuxGuest.GetCurrentSyscallReturnAddress(Instance, Context);

            if (LinuxSignalHelpers.TryActivatePendingSignal(State))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINTR);
                Instance._emulator.WriteRegister(Instance.IPRegister, LinuxGuest.GetCurrentSyscallInstructionAddress(Instance, Context));
                Instance._emulator.StopEmulation();
                return;
            }

            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = -1;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            Thread.State = EmulatedThreadState.Waiting;
            Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINTR);
            Instance._emulator.WriteRegister(Instance.IPRegister, LinuxGuest.GetCurrentSyscallInstructionAddress(Instance, Context));
            Instance._emulator.StopEmulation();
        }
    }
}
