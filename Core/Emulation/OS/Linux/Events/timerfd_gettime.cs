using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal class Timerfd_gettime : ILinuxSyscall
    {
        private readonly bool _time64;

        public Timerfd_gettime(bool time64 = false)
        {
            _time64 = time64;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong curr_value = Context.Arg1;

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

            int Size = GetItimerspecSize(Context);
            if (curr_value == 0 || !Instance.IsRegionMapped(curr_value, (ulong)Size))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            long Now = LinuxEventHelpers.GetClockNanoseconds(Helper, Timerfd.ClockId);
            if (!WriteItimerspec(Instance, Context, curr_value, Timerfd.IntervalNanoseconds, Timerfd.GetRemainingNanoseconds(Now)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

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

        private bool WriteItimerspec(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, long IntervalNanoseconds, long ValueNanoseconds)
        {
            int TimespecSize = GetTimespecSize(Context);
            Span<byte> Buffer = stackalloc byte[32];
            WriteTimespec(Buffer.Slice(0, TimespecSize), TimespecSize, IntervalNanoseconds);
            WriteTimespec(Buffer.Slice(TimespecSize, TimespecSize), TimespecSize, ValueNanoseconds);
            return Instance.WriteMemory(Address, Buffer.Slice(0, TimespecSize * 2));
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
    }
}
