using System.Linq;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Kill : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int pid = unchecked((int)Context.Arg0);
            int sig = unchecked((int)Context.Arg1);

            if (!IsValidSignal(sig))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!MatchesCurrentProcess(Helper, pid))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            if (sig != 0 && !QueueProcessSignal(Instance, Helper, sig))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static bool IsValidSignal(int Signal)
        {
            return Signal >= 0 && Signal < LinuxThreadState.SignalCount;
        }

        private static bool MatchesCurrentProcess(LinuxSyscallsHelper Helper, int Pid)
        {
            return Pid == Helper.PID || Pid == 0 || Pid == -1 || Pid == -Helper.ProcessGroupId;
        }

        private static bool QueueProcessSignal(BinaryEmulator Instance, LinuxSyscallsHelper Helper, int Signal)
        {
            EmulatedThread Target = Instance.CurrentThread;
            if (Target == null || Target.State == EmulatedThreadState.Terminated)
                Target = Instance.Threads.Values.FirstOrDefault(Thread => Thread != null && Thread.State != EmulatedThreadState.Terminated);

            if (Target == null)
                return false;

            LinuxSignalHelpers.QueueSignal(Instance, Helper, Target, new LinuxPendingSignal
            {
                Signal = Signal,
                Code = 0,
                FaultAddress = 0,
                MemoryAccess = default
            });
            return true;
        }
    }
}
