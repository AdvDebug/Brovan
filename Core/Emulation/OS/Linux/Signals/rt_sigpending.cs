using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Signals
{
    internal class Rt_sigpending : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong set = Context.Arg0;
            ulong sigsetsize = Context.Arg1;

            if (!LinuxSignalHelpers.IsValidSignalSetSize(sigsetsize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (set == 0 || !Instance.IsRegionMapped(set, sigsetsize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            LinuxThreadState State = LinuxSignalHelpers.GetOrCreateThreadState(Instance, Helper);
            Span<byte> PendingMask = stackalloc byte[LinuxThreadState.SignalSetSize];
            LinuxSignalHelpers.WritePendingSignals(State, PendingMask);
            if (!Instance.WriteMemory(set, PendingMask.Slice(0, (int)sigsetsize)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
        }
    }
}
