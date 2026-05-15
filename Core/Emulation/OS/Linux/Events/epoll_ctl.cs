using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.Events
{
    internal sealed class Epoll_ctl : ILinuxSyscall
    {
        private const int EPOLL_CTL_ADD = 1;
        private const int EPOLL_CTL_DEL = 2;
        private const int EPOLL_CTL_MOD = 3;
        private const int EpollEventSize = 12;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong epfd = Context.Arg0;
            int op = unchecked((int)Context.Arg1);
            ulong fd = Context.Arg2;
            ulong eventPtr = Context.Arg3;

            FileDescriptorEntry? EpollEntry = Helper.DescriptorTable.GetEntry(epfd);
            if (EpollEntry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (EpollEntry.Object is not EpollObject Epoll)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            FileDescriptorEntry? TargetEntry = Helper.DescriptorTable.GetEntry(fd);
            if (TargetEntry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (fd == epfd)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (TargetEntry.Object is FileObject)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EPERM);
                return;
            }

            uint Events = 0;
            ulong Data = 0;
            if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD)
            {
                if (eventPtr == 0 || !Instance.IsRegionMapped(eventPtr, EpollEventSize))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                Span<byte> EventBytes = stackalloc byte[EpollEventSize];
                if (!Instance.ReadMemory(eventPtr, EventBytes))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                Events = BinaryPrimitives.ReadUInt32LittleEndian(EventBytes.Slice(0, 4));
                Data = BinaryPrimitives.ReadUInt64LittleEndian(EventBytes.Slice(4, 8));

                if ((Events & LinuxEventHelpers.EPOLLEXCLUSIVE) != 0)
                {
                    uint AllowedExclusiveEvents = LinuxEventHelpers.EPOLLIN | LinuxEventHelpers.EPOLLOUT | LinuxEventHelpers.EPOLLERR |
                                                    LinuxEventHelpers.EPOLLHUP | LinuxEventHelpers.EPOLLWAKEUP | LinuxEventHelpers.EPOLLET |
                                                    LinuxEventHelpers.EPOLLEXCLUSIVE;
                    if (op != EPOLL_CTL_ADD || TargetEntry.Object is EpollObject || (Events & ~AllowedExclusiveEvents) != 0)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }
                }
            }

            switch (op)
            {
                case EPOLL_CTL_ADD:
                    if (Epoll.Interests.ContainsKey(fd))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EEXIST);
                        return;
                    }

                    Epoll.Interests[fd] = new EpollInterest
                    {
                        Events = Events,
                        Data = Data,
                        LastReadyEvents = 0,
                        Disabled = false,
                    };
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case EPOLL_CTL_MOD:
                    if (!Epoll.Interests.TryGetValue(fd, out EpollInterest Existing))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                        return;
                    }

                    if ((Events & LinuxEventHelpers.EPOLLEXCLUSIVE) != 0 || (Existing.Events & LinuxEventHelpers.EPOLLEXCLUSIVE) != 0)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                        return;
                    }

                    Existing.Events = Events;
                    Existing.Data = Data;
                    Existing.LastReadyEvents = 0;
                    Existing.Disabled = false;
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                case EPOLL_CTL_DEL:
                    if (!Epoll.Interests.Remove(fd))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;

                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
            }
        }
    }
}
