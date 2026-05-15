using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal sealed class Poll : ILinuxSyscall
    {
        private const int PollfdSize = 8;

        private const short POLLIN = 0x0001;
        private const short POLLPRI = 0x0002;
        private const short POLLOUT = 0x0004;
        private const short POLLERR = 0x0008;
        private const short POLLHUP = 0x0010;
        private const short POLLNVAL = 0x0020;
        private const short POLLRDNORM = 0x0040;
        private const short POLLRDBAND = 0x0080;
        private const short POLLWRNORM = 0x0100;
        private const short POLLWRBAND = 0x0200;
        private const short POLLRDHUP = 0x2000;

        private const short ReadEvents = POLLIN | POLLRDNORM;
        private const short PriorityReadEvents = POLLPRI | POLLRDBAND;
        private const short WriteEvents = POLLOUT | POLLWRNORM;
        private const short PriorityWriteEvents = POLLWRBAND;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong PollfdAddress = Context.Arg0;
            ulong Nfds = unchecked((uint)Context.Arg1);
            int Timeout = unchecked((int)Context.Arg2);

            if (Nfds > SocketHelpers.GetDescriptorLimit(Helper))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (Nfds > (ulong.MaxValue / PollfdSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            ulong PollfdBytes = Nfds * PollfdSize;
            if (PollfdBytes > int.MaxValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                return;
            }

            if (PollfdBytes != 0 && (PollfdAddress == 0 || !Instance.IsRegionMapped(PollfdAddress, PollfdBytes)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            TimeSpan? TimeoutSpan = Timeout < 0 ? null : TimeSpan.FromMilliseconds(Timeout);
            Stopwatch Timer = Stopwatch.StartNew();

            while (true)
            {
                Span<byte> Pollfds = PollfdBytes == 0 ? Span<byte>.Empty : Helper.Shared.GetSpan(PollfdBytes);
                if (PollfdBytes != 0 && !Instance.ReadMemory(PollfdAddress, Pollfds))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                int ReadyCount = BuildRevents(Instance, Helper, Pollfds, Nfds);

                if (ReadyCount != 0 || Timeout == 0 || (TimeoutSpan.HasValue && Timer.Elapsed >= TimeoutSpan.Value))
                {
                    if (PollfdBytes != 0 && !Instance.WriteMemory(PollfdAddress, Pollfds))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, ReadyCount);
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

        private static short GetRevents(IFileDescriptorObject Object, short Events)
        {
            switch (Object)
            {
                case FileObject:
                    return GetFileRevents(Events);
                case SocketObject SocketDescriptor:
                    return GetSocketRevents(SocketDescriptor, Events);
                default:
                    return POLLNVAL;
            }
        }

        private static short GetFileRevents(short Events)
        {
            short Revents = 0;

            if ((Events & ReadEvents) != 0)
                Revents |= (short)(Events & ReadEvents);

            if ((Events & WriteEvents) != 0)
                Revents |= (short)(Events & WriteEvents);

            return Revents;
        }

        private static short GetSocketRevents(SocketObject SocketDescriptor, short Events)
        {
            short Revents = 0;

            if (SocketDescriptor.PendingConnect != null)
            {
                if (!SocketDescriptor.PendingConnectCompleted)
                    return 0;

                if (SocketDescriptor.PendingConnect.SocketError == SocketError.Success)
                {
                    if ((Events & WriteEvents) != 0)
                        Revents |= (short)(Events & WriteEvents);
                }
                else
                {
                    Revents |= POLLERR;
                }

                return Revents;
            }

            if ((Events & ReadEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectRead))
                Revents |= (short)(Events & ReadEvents);

            if ((Events & PriorityReadEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectError))
                Revents |= (short)(Events & PriorityReadEvents);

            if ((Events & WriteEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectWrite))
                Revents |= (short)(Events & WriteEvents);

            if ((Events & PriorityWriteEvents) != 0 && IsSocketReady(SocketDescriptor, SelectMode.SelectWrite))
                Revents |= (short)(Events & PriorityWriteEvents);

            if (IsSocketReady(SocketDescriptor, SelectMode.SelectError))
                Revents |= POLLERR;

            if (IsSocketReady(SocketDescriptor, SelectMode.SelectRead) && IsPeerShutdown(SocketDescriptor))
                Revents |= POLLHUP | POLLRDHUP;

            return Revents;
        }

        private static bool IsPeerShutdown(SocketObject SocketDescriptor)
        {
            try
            {
                return SocketDescriptor.Handle.Available == 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSocketReady(SocketObject SocketDescriptor, SelectMode Mode)
        {
            try
            {
                return SocketDescriptor.Handle.Poll(0, Mode);
            }
            catch
            {
                return true;
            }
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
