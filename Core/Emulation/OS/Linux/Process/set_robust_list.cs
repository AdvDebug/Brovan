using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Set_robust_list : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong ExpectedSize = Context.Abi == SyscallAbi.X64 ? 24UL : 12UL;
            if (Context.Arg1 != ExpectedSize)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            LinuxThreadState State = Instance.CurrentThread?.GuestState as LinuxThreadState;
            if (State == null && Instance.CurrentThread != null)
            {
                State = new LinuxThreadState()
                {
                    CpuidEnabled = Helper.CpuidEnabled
                };

                if (Instance.IsX64Guest)
                {
                    State.FsBase = Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE);
                    State.GsBase = Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE);
                }

                Instance.CurrentThread.GuestState = State;
            }

            if (State != null)
            {
                State.RobustListHead = Context.Arg0;
                State.RobustListLength = Context.Arg1;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }
    }
}
