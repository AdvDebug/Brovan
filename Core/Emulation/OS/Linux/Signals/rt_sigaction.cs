using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Rt_sigaction : ILinuxSyscall
    {
        private const int SIGKILL = 9;
        private const int SIGSTOP = 19;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int signum = unchecked((int)Context.Arg0);
            ulong act = Context.Arg1;
            ulong oldact = Context.Arg2;
            ulong sigsetsize = Context.Arg3;

            if (!IsValidSignal(signum) || signum == SIGKILL || signum == SIGSTOP || !LinuxSignalHelpers.IsValidSignalSetSize(sigsetsize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int ActionSize = LinuxSignalHelpers.GetSigActionSize(Context, sigsetsize);
            byte[] OldAction = Helper.GetSignalAction(signum, ActionSize);
            if (oldact != 0)
            {
                if (!Instance.IsRegionMapped(oldact, (ulong)ActionSize) || !Instance.WriteMemory(oldact, OldAction))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            if (act != 0)
            {
                if (!Instance.IsRegionMapped(act, (ulong)ActionSize))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                Helper.SetSignalAction(signum, Instance.ReadMemory(act, (uint)ActionSize));
            }

            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }

        private static bool IsValidSignal(int Signal)
        {
            return Signal > 0 && Signal < LinuxThreadState.SignalCount;
        }
    }
}
