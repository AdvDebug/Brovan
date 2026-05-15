using System;
using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Process
{
    internal class Prlimit64 : ILinuxSyscall
    {
        private const int RLIMIT_CPU = 0;
        private const int RLIMIT_FSIZE = 1;
        private const int RLIMIT_DATA = 2;
        private const int RLIMIT_STACK = 3;
        private const int RLIMIT_CORE = 4;
        private const int RLIMIT_RSS = 5;
        private const int RLIMIT_NPROC = 6;
        private const int RLIMIT_NOFILE = 7;
        private const int RLIMIT_MEMLOCK = 8;
        private const int RLIMIT_AS = 9;
        private const int RLIMIT_LOCKS = 10;
        private const int RLIMIT_SIGPENDING = 11;
        private const int RLIMIT_MSGQUEUE = 12;
        private const int RLIMIT_NICE = 13;
        private const int RLIMIT_RTPRIO = 14;
        private const int RLIMIT_RTTIME = 15;
        private const int RLIM_NLIMITS = 16;
        private const ulong RLIM_INFINITY = ulong.MaxValue;
        private const ulong DefaultStackLimit = 8UL * 1024UL * 1024UL;
        private const ulong DefaultMemlockLimit = 8UL * 1024UL * 1024UL;
        private const ulong DefaultNoFileLimit = 1024UL;
        private const ulong DefaultSigpendingLimit = 256UL * 1024UL;
        private const ulong DefaultMsgqueueLimit = 819200UL;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int Pid = unchecked((int)Context.Arg0);
            int Resource = unchecked((int)Context.Arg1);
            ulong NewLimitPointer = Context.Arg2;
            ulong OldLimitPointer = Context.Arg3;

            if ((uint)Resource >= RLIM_NLIMITS)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (Pid != 0 && Pid != Helper.PID)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ESRCH);
                return;
            }

            LinuxResourceLimit PreviousLimit = GetResourceLimit(Helper, Resource);
            LinuxResourceLimit NextLimit = PreviousLimit;

            if (NewLimitPointer != 0)
            {
                if (!Instance.IsRegionMapped(NewLimitPointer, 16))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                Span<byte> RawNewLimit = stackalloc byte[16];
                if (!Instance.ReadMemory(NewLimitPointer, RawNewLimit))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                NextLimit = new LinuxResourceLimit()
                {
                    Current = BinaryPrimitives.ReadUInt64LittleEndian(RawNewLimit.Slice(0, 8)),
                    Maximum = BinaryPrimitives.ReadUInt64LittleEndian(RawNewLimit.Slice(8, 8)),
                };

                if (NextLimit.Current > NextLimit.Maximum)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }

                if (NextLimit.Maximum > PreviousLimit.Maximum || NextLimit.Current > PreviousLimit.Maximum)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EPERM);
                    return;
                }
            }

            if (OldLimitPointer != 0)
            {
                if (!Instance.IsRegionMapped(OldLimitPointer, 16))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            if (OldLimitPointer != 0)
            {
                Span<byte> OldLimitBytes = stackalloc byte[16];
                BinaryPrimitives.WriteUInt64LittleEndian(OldLimitBytes.Slice(0, 8), PreviousLimit.Current);
                BinaryPrimitives.WriteUInt64LittleEndian(OldLimitBytes.Slice(8, 8), PreviousLimit.Maximum);

                if (!Instance.WriteMemory(OldLimitPointer, OldLimitBytes))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }

            if (NewLimitPointer != 0)
                Helper.ResourceLimits[Resource] = NextLimit;

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static LinuxResourceLimit GetResourceLimit(LinuxSyscallsHelper Helper, int Resource)
        {
            if (Helper.ResourceLimits.TryGetValue(Resource, out LinuxResourceLimit Limit))
                return Limit;

            return new LinuxResourceLimit()
            {
                Current = GetDefaultSoftLimit(Resource),
                Maximum = GetDefaultHardLimit(Resource),
            };
        }

        private static ulong GetDefaultSoftLimit(int Resource)
        {
            switch (Resource)
            {
                case RLIMIT_STACK:
                    return DefaultStackLimit;
                case RLIMIT_CORE:
                    return 0;
                case RLIMIT_NOFILE:
                    return DefaultNoFileLimit;
                case RLIMIT_MEMLOCK:
                    return DefaultMemlockLimit;
                case RLIMIT_SIGPENDING:
                    return DefaultSigpendingLimit;
                case RLIMIT_MSGQUEUE:
                    return DefaultMsgqueueLimit;
                case RLIMIT_NICE:
                    return 0;
                case RLIMIT_RTPRIO:
                    return 0;
                case RLIMIT_CPU:
                case RLIMIT_FSIZE:
                case RLIMIT_DATA:
                case RLIMIT_RSS:
                case RLIMIT_NPROC:
                case RLIMIT_AS:
                case RLIMIT_LOCKS:
                case RLIMIT_RTTIME:
                    return RLIM_INFINITY;
                default:
                    return RLIM_INFINITY;
            }
        }

        private static ulong GetDefaultHardLimit(int Resource)
        {
            switch (Resource)
            {
                case RLIMIT_CORE:
                    return RLIM_INFINITY;
                default:
                    return GetDefaultSoftLimit(Resource);
            }
        }
    }
}
