using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Rt_sigprocmask : ILinuxSyscall
    {
        private const int SIG_BLOCK = 0;
        private const int SIG_UNBLOCK = 1;
        private const int SIG_SETMASK = 2;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int how = unchecked((int)Context.Arg0);
            ulong set = Context.Arg1;
            ulong oldset = Context.Arg2;
            ulong sigsetsize = Context.Arg3;

            if (!LinuxSignalHelpers.IsValidSignalSetSize(sigsetsize) || (set != 0 && how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            LinuxThreadState State = LinuxSignalHelpers.GetOrCreateThreadState(Instance, Helper);
            if (State == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int MaskSize = (int)sigsetsize;
            if (oldset != 0)
            {
                if (!Instance.IsRegionMapped(oldset, (ulong)MaskSize) || !Instance.WriteMemory(oldset, State.SignalMask.AsSpan(0, MaskSize)))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            if (set != 0)
            {
                if (!Instance.IsRegionMapped(set, (ulong)MaskSize))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                byte[] IncomingMask = Instance.ReadMemory(set, (uint)MaskSize);
                LinuxSignalHelpers.ClearUnblockableSignals(IncomingMask);
                switch (how)
                {
                    case SIG_BLOCK:
                        for (int i = 0; i < MaskSize; i++)
                            State.SignalMask[i] |= IncomingMask[i];
                        LinuxSignalHelpers.ClearUnblockableSignals(State.SignalMask);
                        break;

                    case SIG_UNBLOCK:
                        for (int i = 0; i < MaskSize; i++)
                            State.SignalMask[i] &= unchecked((byte)~IncomingMask[i]);
                        break;

                    case SIG_SETMASK:
                        Array.Clear(State.SignalMask, 0, State.SignalMask.Length);
                        Buffer.BlockCopy(IncomingMask, 0, State.SignalMask, 0, MaskSize);
                        LinuxSignalHelpers.ClearUnblockableSignals(State.SignalMask);
                        break;
                }
            }

            LinuxSignalHelpers.TryActivatePendingSignal(State);
            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}
