using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Threading;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal sealed class Poll : ILinuxSyscall
    {
        private const int PollfdSize = 8;

        private const short POLLNVAL = 0x0020;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong PollfdAddress = Context.Arg0;
            ulong Nfds = unchecked((uint)Context.Arg1);
            int Timeout = unchecked((int)Context.Arg2);

            if (Nfds > SocketHelpers.GetDescriptorLimit(Helper))
            {
                Helper.SetReturnValue(Instance, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (Nfds > (ulong.MaxValue / PollfdSize))
            {
                Helper.SetReturnValue(Instance, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong PollfdBytes = Nfds * PollfdSize;
            if (PollfdBytes > int.MaxValue)
            {
                Helper.SetReturnValue(Instance, -(long)LinuxErrno.ENOMEM);
                return;
            }

            if (PollfdBytes != 0 && (PollfdAddress == 0 || !Instance.IsRegionMapped(PollfdAddress, PollfdBytes)))
            {
                Helper.SetReturnValue(Instance, -(long)LinuxErrno.EFAULT);
                return;
            }

            TimeSpan? TimeoutSpan = Timeout < 0 ? null : TimeSpan.FromMilliseconds(Timeout);
            Stopwatch Timer = Stopwatch.StartNew();

            while (true)
            {
                Span<byte> Pollfds = PollfdBytes == 0 ? Span<byte>.Empty : Helper.Shared.GetSpan(PollfdBytes);
                if (PollfdBytes != 0 && !Instance.ReadMemory(PollfdAddress, Pollfds))
                {
                    Helper.SetReturnValue(Instance, -(long)LinuxErrno.EFAULT);
                    return;
                }

                int ReadyCount = BuildRevents(Instance, Helper, Pollfds, Nfds);

                if (ReadyCount != 0 || Timeout == 0 || (TimeoutSpan.HasValue && Timer.Elapsed >= TimeoutSpan.Value))
                {
                    if (PollfdBytes != 0 && !Instance.WriteMemory(PollfdAddress, Pollfds))
                    {
                        Helper.SetReturnValue(Instance, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, ReadyCount);
                    return;
                }

                SleepUntilNextPoll(TimeoutSpan, Timer.Elapsed);
            }
        }

        private static int BuildRevents(BinaryEmulator Instance, LinuxSyscallsHelper Helper, Span<byte> Pollfds, ulong Nfds)
        {
            int ReadyCount = 0;

            for (ulong Index = 0; Index < Nfds; Index++)
            {
                int Offset = checked((int)(Index * PollfdSize));
                int Descriptor = BinaryPrimitives.ReadInt32LittleEndian(Pollfds.Slice(Offset, 4));
                short Events = BinaryPrimitives.ReadInt16LittleEndian(Pollfds.Slice(Offset + 4, 2));
                short Revents = 0;

                if (Descriptor < 0)
                {
                    WriteRevents(Pollfds, Offset, 0);
                    continue;
                }

                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry((ulong)Descriptor);
                if (Entry == null)
                {
                    Revents = POLLNVAL;
                    WriteRevents(Pollfds, Offset, Revents);
                    ReadyCount++;
                    continue;
                }

                Revents = unchecked((short)LinuxEventHelpers.GetReadyEvents(Instance, Helper, Entry.Object, unchecked((ushort)Events)));
                WriteRevents(Pollfds, Offset, Revents);

                if (Revents != 0)
                    ReadyCount++;
            }

            return ReadyCount;
        }

        private static void WriteRevents(Span<byte> Pollfds, int Offset, short Revents)
        {
            BinaryPrimitives.WriteInt16LittleEndian(Pollfds.Slice(Offset + 6, 2), Revents);
        }

        private static void SleepUntilNextPoll(TimeSpan? Timeout, TimeSpan Elapsed)
        {
            if (!Timeout.HasValue)
            {
                Thread.Sleep(1);
                return;
            }

            TimeSpan Remaining = Timeout.Value - Elapsed;
            if (Remaining <= TimeSpan.Zero)
                return;

            int SleepMilliseconds = Math.Max(1, Math.Min(10, (int)Math.Ceiling(Remaining.TotalMilliseconds)));
            Thread.Sleep(SleepMilliseconds);
        }
    }
}
