using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Rseq : ILinuxSyscall
    {
        private const int RSEQ_FLAG_UNREGISTER = 1;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong RseqPointer = Context.Arg0;
            uint RseqLength = (uint)Context.Arg1;
            int Flags = unchecked((int)Context.Arg2);
            uint Signature = (uint)Context.Arg3;
            EmulatedThread Thread = Instance.CurrentThread;
            LinuxThreadState State = Thread?.GuestState as LinuxThreadState;
            if (State == null && Thread != null)
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

                Thread.GuestState = State;
            }

            if (Thread == null || State == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            if ((Flags & RSEQ_FLAG_UNREGISTER) != 0)
            {
                if ((Flags & ~RSEQ_FLAG_UNREGISTER) != 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (State.RseqPointer != RseqPointer || State.RseqPointer == 0 || State.RseqLength == 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (State.RseqLength != RseqLength)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (State.RseqSignature != Signature)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EPERM);
                    return;
                }

                if (!LinuxGuest.TryResetRegisteredRseq(Instance, State))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                State.RseqPointer = 0;
                State.RseqLength = 0;
                State.RseqSignature = 0;
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (Flags != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (State.RseqPointer != 0 || State.RseqLength != 0)
            {
                if (State.RseqPointer != RseqPointer || State.RseqLength != RseqLength)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (State.RseqSignature != Signature)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EPERM);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBUSY);
                return;
            }

            if (RseqLength < LinuxGuest.RseqOriginalSize)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((RseqPointer & (LinuxGuest.RseqAlignment - 1)) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (RseqLength != LinuxGuest.RseqOriginalSize && RseqLength < LinuxGuest.RseqMinimumFeatureSize)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsRegionMapped(RseqPointer, RseqLength))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            State.RseqPointer = RseqPointer;
            State.RseqLength = RseqLength;
            State.RseqSignature = Signature;

            if (!LinuxGuest.TryWriteRegisteredRseq(Instance, Thread, State, true))
            {
                State.RseqPointer = 0;
                State.RseqLength = 0;
                State.RseqSignature = 0;
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }
    }
}
