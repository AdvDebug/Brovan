using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Set_tid_address : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
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
                State.TIDPtr = Context.Arg0;

            ulong ThreadId = Instance.CurrentThread != null ? Instance.CurrentThread.ThreadId : (ulong)(uint)Instance.CurrentThreadId;
            Helper.SetReturnValue(Instance, Context, ThreadId);
        }
    }
}