using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal class Timerfd_settime : ILinuxSyscall
    {
        private const int TFD_TIMER_ABSTIME = 1;
        private const int TFD_TIMER_CANCEL_ON_SET = 2;
        private const int ValidFlags = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;
        private const long NanosecondsPerSecond = 1000000000L;
        private readonly bool _time64;

        public Timerfd_settime(bool time64 = false)
        {
            _time64 = time64;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            int flags = unchecked((int)Context.Arg1);
            ulong new_value = Context.Arg2;
            ulong old_value = Context.Arg3;

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (Entry.Object is not TimerfdObject Timerfd)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((flags & ~ValidFlags) != 0 || new_value == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int Size = GetItimerspecSize(Context);
            if (!Instance.IsRegionMapped(new_value, (ulong)Size) || (old_value != 0 && !Instance.IsRegionMapped(old_value, (ulong)Size)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            long Now = LinuxEventHelpers.GetClockNanoseconds(Helper, Timerfd.ClockId);
            if (old_value != 0 && !WriteItimerspec(Instance, Context, old_value, Timerfd.IntervalNanoseconds, Timerfd.GetRemainingNanoseconds(Now)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!ReadItimerspec(Instance, Context, new_value, out long IntervalNanoseconds, out long ValueNanoseconds))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (IntervalNanoseconds < 0 || ValueNanoseconds < 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (ValueNanoseconds == 0)
            {
                Timerfd.Disarm();
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            bool Absolute = (flags & TFD_TIMER_ABSTIME) != 0;
            long NextExpiration = Absolute ? ValueNanoseconds : AddClamp(Now, ValueNanoseconds);
            if (NextExpiration <= Now)
                NextExpiration = Now;

            Timerfd.Arm(NextExpiration, IntervalNanoseconds, Absolute);
            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private int GetTimespecSize(LinuxSyscallContext Context)
        {
            return Context.Abi == SyscallAbi.X64 || _time64 ? 16 : 8;
        }

        private int GetItimerspecSize(LinuxSyscallContext Context)
        {
            return GetTimespecSize(Context) * 2;
        }

        private bool ReadItimerspec(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, out long IntervalNanoseconds, out long ValueNanoseconds)
        {
            int TimespecSize = GetTimespecSize(Context);
            int ItimerspecSize = TimespecSize * 2;
            Span<byte> Buffer = stackalloc byte[32];
            if (!Instance.ReadMemory(Address, Buffer.Slice(0, ItimerspecSize)))
            {
                IntervalNanoseconds = 0;
                ValueNanoseconds = 0;
                return false;
            }

            if (!TryReadTimespec(Buffer.Slice(0, TimespecSize), TimespecSize, out long IntervalSeconds, out long IntervalNanos) ||
                !TryReadTimespec(Buffer.Slice(TimespecSize, TimespecSize), TimespecSize, out long ValueSeconds, out long ValueNanos))
            {
                IntervalNanoseconds = -1;
                ValueNanoseconds = -1;
                return true;
            }

            IntervalNanoseconds = LinuxEventHelpers.TimespecToNanoseconds(IntervalSeconds, IntervalNanos);
            ValueNanoseconds = LinuxEventHelpers.TimespecToNanoseconds(ValueSeconds, ValueNanos);
            return true;
        }

        private bool WriteItimerspec(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, long IntervalNanoseconds, long ValueNanoseconds)
        {
            int TimespecSize = GetTimespecSize(Context);
            Span<byte> Buffer = stackalloc byte[32];
            WriteTimespec(Buffer.Slice(0, TimespecSize), TimespecSize, IntervalNanoseconds);
            WriteTimespec(Buffer.Slice(TimespecSize, TimespecSize), TimespecSize, ValueNanoseconds);
            return Instance.WriteMemory(Address, Buffer.Slice(0, TimespecSize * 2));
        }

        private static bool TryReadTimespec(ReadOnlySpan<byte> Buffer, int TimespecSize, out long Seconds, out long Nanoseconds)
        {
            if (TimespecSize == 16)
            {
                Seconds = BinaryPrimitives.ReadInt64LittleEndian(Buffer.Slice(0, 8));
                Nanoseconds = BinaryPrimitives.ReadInt64LittleEndian(Buffer.Slice(8, 8));
            }
            else
            {
                Seconds = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0, 4));
                Nanoseconds = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(4, 4));
            }

            return Seconds >= 0 && Nanoseconds >= 0 && Nanoseconds < NanosecondsPerSecond;
        }

        private static void WriteTimespec(Span<byte> Buffer, int TimespecSize, long Nanoseconds)
        {
            LinuxEventHelpers.NanosecondsToTimespec(Nanoseconds, out long Seconds, out long RemainderNanoseconds);
            if (TimespecSize == 16)
            {
                BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0, 8), Seconds);
                BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(8, 8), RemainderNanoseconds);
            }
            else
            {
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0, 4), Seconds > int.MaxValue ? int.MaxValue : (int)Seconds);
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4, 4), (int)RemainderNanoseconds);
            }
        }

        private static long AddClamp(long Left, long Right)
        {
            return Right > long.MaxValue - Left ? long.MaxValue : Left + Right;
        }
    }
}
