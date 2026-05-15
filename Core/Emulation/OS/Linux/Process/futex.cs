using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Futex : ILinuxSyscall
    {
        private const int FUTEX_WAIT = 0;
        private const int FUTEX_WAKE = 1;
        private const int FUTEX_WAIT_BITSET = 9;
        private const int FUTEX_WAKE_BITSET = 10;
        private const int FUTEX_CMD_MASK = 0x7F;
        private const uint FUTEX_BITSET_MATCH_ANY = 0xFFFFFFFF;
        private readonly bool _time64;

        public Futex(bool time64 = false)
        {
            _time64 = time64;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            LinuxThreadState State = Thread?.GuestState as LinuxThreadState;
            if (State != null && State.FutexWaitCompleted)
            {
                long Result = State.FutexWaitResult;
                State.FutexWaitCompleted = false;
                State.FutexWaitActive = false;
                State.FutexAddress = 0;
                State.FutexBitset = 0;
                Helper.SetReturnValue(Instance, Context, Result);
                return;
            }

            ulong uaddr = Context.Arg0;
            int futex_op = unchecked((int)Context.Arg1);
            uint val = (uint)Context.Arg2;
            ulong timeout = Context.Arg3;
            uint val3 = (uint)Context.Arg5;
            int Command = futex_op & FUTEX_CMD_MASK;

            switch (Command)
            {
                case FUTEX_WAIT:
                    Wait(Instance, Helper, Context, Thread, State, uaddr, val, timeout, FUTEX_BITSET_MATCH_ANY);
                    return;

                case FUTEX_WAIT_BITSET:
                    Wait(Instance, Helper, Context, Thread, State, uaddr, val, timeout, val3);
                    return;

                case FUTEX_WAKE:
                    Wake(Instance, Helper, Context, uaddr, val, FUTEX_BITSET_MATCH_ANY);
                    return;

                case FUTEX_WAKE_BITSET:
                    Wake(Instance, Helper, Context, uaddr, val, val3);
                    return;

                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOSYS);
                    return;
            }
        }

        private void Wait(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, EmulatedThread Thread, LinuxThreadState State, ulong uaddr, uint ExpectedValue, ulong timeout, uint Bitset)
        {
            if (Thread == null || State == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((uaddr & 3) != 0 || Bitset == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsRegionMapped(uaddr, 4))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            uint CurrentValue = BitConverter.ToUInt32(Instance.ReadMemory(uaddr, 4), 0);
            if (CurrentValue != ExpectedValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            long Deadline = -1;
            if (timeout != 0)
            {
                if (!TryParseTimeout(Instance, Context, timeout, out long TimeoutMilliseconds))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (TimeoutMilliseconds == 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ETIMEDOUT);
                    return;
                }

                Deadline = Instance.EmulatedTickCount64 + TimeoutMilliseconds;
                if (Deadline < Instance.EmulatedTickCount64)
                    Deadline = long.MaxValue;
            }

            State.FutexWaitActive = true;
            State.FutexWaitCompleted = false;
            State.FutexWaitResult = 0;
            State.FutexAddress = uaddr;
            State.FutexBitset = Bitset;
            State.FutexWaitResumeRIP = LinuxGuest.GetCurrentSyscallInstructionAddress(Instance, Context);
            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = Deadline;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            Thread.State = EmulatedThreadState.Waiting;
            Helper.AddFutexWaiter(uaddr, Thread);
            Helper.SetReturnValue(Instance, Context, 0L);
            Instance._emulator.WriteRegister(Instance.IPRegister, State.FutexWaitResumeRIP);
            Instance._emulator.StopEmulation();
        }

        private static void Wake(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong uaddr, uint Count, uint Bitset)
        {
            if ((uaddr & 3) != 0 || Bitset == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            uint Woken = Helper.WakeFutexWaiters(Instance, uaddr, Count, Bitset);
            Helper.SetReturnValue(Instance, Context, Woken);
        }

        private bool TryParseTimeout(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, out long TimeoutMilliseconds)
        {
            TimeoutMilliseconds = 0;
            int Size = _time64 || Context.Abi == SyscallAbi.X64 ? 16 : 8;
            if (!Instance.IsRegionMapped(Address, (ulong)Size))
                return false;

            byte[] Buffer = Instance.ReadMemory(Address, (uint)Size);
            long Seconds;
            long Nanoseconds;
            if (_time64 || Context.Abi == SyscallAbi.X64)
            {
                Seconds = BitConverter.ToInt64(Buffer, 0);
                Nanoseconds = BitConverter.ToInt64(Buffer, 8);
            }
            else
            {
                Seconds = BitConverter.ToInt32(Buffer, 0);
                Nanoseconds = BitConverter.ToInt32(Buffer, 4);
            }

            if (Seconds < 0 || Nanoseconds < 0 || Nanoseconds > 999999999)
                return false;

            ulong Milliseconds = (ulong)Seconds * 1000UL + (ulong)((Nanoseconds + 999999) / 1000000);
            TimeoutMilliseconds = Milliseconds > long.MaxValue ? long.MaxValue : (long)Milliseconds;
            return true;
        }
    }
}
