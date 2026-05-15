using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Tkill : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int tid = unchecked((int)Context.Arg0);
            int sig = unchecked((int)Context.Arg1);
            LinuxSignalSyscallHelpers.HandleThreadSignal(Instance, Helper, Context, 0, tid, sig, true);
        }
    }
}
