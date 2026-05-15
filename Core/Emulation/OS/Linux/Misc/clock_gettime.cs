using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal sealed class Clock_gettime : ILinuxSyscall
    {
        private const int CLOCK_REALTIME = 0;
        private const int CLOCK_MONOTONIC = 1;
        private const int CLOCK_PROCESS_CPUTIME_ID = 2;
        private const int CLOCK_THREAD_CPUTIME_ID = 3;
        private const int CLOCK_MONOTONIC_RAW = 4;
        private const int CLOCK_REALTIME_COARSE = 5;
        private const int CLOCK_MONOTONIC_COARSE = 6;
        private const int CLOCK_BOOTTIME = 7;
        private const int CLOCK_REALTIME_ALARM = 8;
        private const int CLOCK_BOOTTIME_ALARM = 9;
        private const int CLOCK_TAI = 11;

        private readonly bool _useTime64LayoutOnX86;

        public Clock_gettime(bool UseTime64LayoutOnX86 = false)
        {
            _useTime64LayoutOnX86 = UseTime64LayoutOnX86;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int ClockId = unchecked((int)Context.Arg0);
            ulong TimePointer = Context.Arg1;

            if (TimePointer == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!TryGetClockValue(Helper, ClockId, out long Seconds, out long Nanoseconds))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!TryWriteTimespec(Instance, Context, TimePointer, Seconds, Nanoseconds, _useTime64LayoutOnX86))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static bool TryGetClockValue(LinuxSyscallsHelper Helper, int ClockId, out long Seconds, out long Nanoseconds)
        {
            switch (ClockId)
            {
                case CLOCK_REALTIME:
                case CLOCK_REALTIME_COARSE:
                case CLOCK_REALTIME_ALARM:
                case CLOCK_TAI:
                    return TryGetRealtimeValue(Helper, out Seconds, out Nanoseconds);
                case CLOCK_MONOTONIC:
                case CLOCK_MONOTONIC_RAW:
                case CLOCK_MONOTONIC_COARSE:
                case CLOCK_BOOTTIME:
                case CLOCK_BOOTTIME_ALARM:
                    return TryGetSystemUptimeValue(Helper, out Seconds, out Nanoseconds);
                case CLOCK_PROCESS_CPUTIME_ID:
                case CLOCK_THREAD_CPUTIME_ID:
                    return TryGetRuntimeValue(Helper, out Seconds, out Nanoseconds);
                default:
                    Seconds = 0;
                    Nanoseconds = 0;
                    return false;
            }
        }

        private static bool TryGetRealtimeValue(LinuxSyscallsHelper Helper, out long Seconds, out long Nanoseconds)
        {
            DateTimeOffset Value = Helper.GetRealtimeNowUtc();
            return TryConvertDateTimeOffset(Value, out Seconds, out Nanoseconds);
        }

        private static bool TryGetSystemUptimeValue(LinuxSyscallsHelper Helper, out long Seconds, out long Nanoseconds)
        {
            return TryConvertTimeSpan(Helper.GetSystemUptime(), out Seconds, out Nanoseconds);
        }

        private static bool TryGetRuntimeValue(LinuxSyscallsHelper Helper, out long Seconds, out long Nanoseconds)
        {
            return TryConvertTimeSpan(Helper.GetClockElapsed(), out Seconds, out Nanoseconds);
        }

        private static bool TryConvertDateTimeOffset(DateTimeOffset Value, out long Seconds, out long Nanoseconds)
        {
            DateTimeOffset UtcValue = Value.ToUniversalTime();
            Seconds = UtcValue.ToUnixTimeSeconds();
            Nanoseconds = (UtcValue.Ticks % TimeSpan.TicksPerSecond) * 100;
            if (Nanoseconds < 0)
                Nanoseconds = 0;

            return true;
        }

        private static bool TryConvertTimeSpan(TimeSpan Value, out long Seconds, out long Nanoseconds)
        {
            if (Value < TimeSpan.Zero)
                Value = TimeSpan.Zero;

            Seconds = Value.Ticks / TimeSpan.TicksPerSecond;
            Nanoseconds = (Value.Ticks % TimeSpan.TicksPerSecond) * 100;
            if (Nanoseconds < 0)
                Nanoseconds = 0;

            return true;
        }

        private static bool TryWriteTimespec(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, long Seconds, long Nanoseconds, bool UseTime64LayoutOnX86)
        {
            if (Context.Abi == SyscallAbi.X64 || UseTime64LayoutOnX86)
            {
                if (!Instance.IsRegionMapped(Address, 16))
                    return false;

                Span<byte> Buffer = stackalloc byte[16];
                BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0, 8), Seconds);
                BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(8, 8), Nanoseconds);
                return Instance.WriteMemory(Address, Buffer);
            }

            if (!Instance.IsRegionMapped(Address, 8))
                return false;

            int Seconds32 = Seconds <= int.MinValue ? int.MinValue : Seconds >= int.MaxValue ? int.MaxValue : (int)Seconds;
            int Nanoseconds32 = Nanoseconds <= int.MinValue ? int.MinValue : Nanoseconds >= int.MaxValue ? int.MaxValue : (int)Nanoseconds;
            Span<byte> Buffer32 = stackalloc byte[8];
            BinaryPrimitives.WriteInt32LittleEndian(Buffer32.Slice(0, 4), Seconds32);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer32.Slice(4, 4), Nanoseconds32);
            return Instance.WriteMemory(Address, Buffer32);
        }
    }
}
