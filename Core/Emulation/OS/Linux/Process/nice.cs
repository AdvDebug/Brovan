using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Nice : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int inc = unchecked((int)Context.Arg0);
            LinuxThreadState CurrentThread = Instance.CurrentThread?.GuestState as LinuxThreadState;
            if (CurrentThread == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int OldNice = CurrentThread.NiceValue;
            int NewNice = OldNice + inc;

            // Linux nice values are clamped to the range [-20, 19].
            if (NewNice < -20)
                NewNice = -20;
            else if (NewNice > 19)
                NewNice = 19;

            if (NewNice < OldNice)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EPERM);
                return;
            }

            CurrentThread.NiceValue = NewNice;
            Helper.SetReturnValue(Instance, Context, (long)NewNice);
        }
    }
}
