using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Tgkill : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int tgid = unchecked((int)Context.Arg0);
            int tid = unchecked((int)Context.Arg1);
            int sig = unchecked((int)Context.Arg2);
            LinuxSignalSyscallHelpers.HandleThreadSignal(Instance, Helper, Context, tgid, tid, sig, false);
        }
    }
}
