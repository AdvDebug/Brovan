using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Sigaltstack : ILinuxSyscall
    {
        private const int SS_ONSTACK = 1;
        private const int SS_DISABLE = 2;
        private const ulong MINSIGSTKSZ = 2048;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong ss = Context.Arg0;
            ulong old_ss = Context.Arg1;
            LinuxThreadState State = LinuxSignalHelpers.GetOrCreateThreadState(Instance, Helper);
            if (State == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int StackSize = Context.Abi == SyscallAbi.X64 ? 24 : 12;
            if (old_ss != 0)
            {
                LinuxSignalStack OldStack = State.AlternateSignalStack;
                if (State.SignalStackActive)
                    OldStack.Flags = SS_ONSTACK;

                if (!Instance.IsRegionMapped(old_ss, (ulong)StackSize) || !LinuxSignalHelpers.WriteStackT(Instance, Context, old_ss, OldStack))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            if (ss != 0)
            {
                if (!Instance.IsRegionMapped(ss, (ulong)StackSize))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                if (State.SignalStackActive)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EPERM);
                    return;
                }

                LinuxSignalStack NewStack = LinuxSignalHelpers.ReadStackT(Instance, Context, ss);
                if ((NewStack.Flags & ~(SS_ONSTACK | SS_DISABLE)) != 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if ((NewStack.Flags & SS_DISABLE) == 0 && NewStack.Size < MINSIGSTKSZ)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                    return;
                }

                State.AlternateSignalStack = NewStack;
            }

            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}
