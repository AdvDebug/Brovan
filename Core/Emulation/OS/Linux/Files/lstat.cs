namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Lstat : ILinuxSyscall
    {
        private readonly bool _useCompat64;

        public Lstat(bool UseCompat64 = false)
        {
            _useCompat64 = UseCompat64;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong path = Context.Arg0;
            ulong statbuf = Context.Arg1;

            if (!_useCompat64 && Context.Abi == SyscallAbi.X86)
            {
                LinuxErrno Error32 = Stat.WriteStat32(Instance, Helper, path, statbuf, true);
                Helper.SetReturnValue(Instance, Context, Error32 == LinuxErrno.ESUCCESS ? 0L : -(long)Error32);
                return;
            }

            LinuxErrno Error = LinuxStatHelper.WritePathStat(Instance, Helper, Context, path, statbuf, _useCompat64 ? LinuxStatVariant.Compat64 : LinuxStatVariant.Native, false);
            Helper.SetReturnValue(Instance, Context, Error == LinuxErrno.ESUCCESS ? 0L : -(long)Error);
        }
    }
}
