using System;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal sealed class Fcntl : ILinuxSyscall
    {
        private const int F_DUPFD = 0;
        private const int F_GETFD = 1;
        private const int F_SETFD = 2;
        private const int F_GETFL = 3;
        private const int F_SETFL = 4;
        private const int F_DUPFD_CLOEXEC = 1030;

        private const int FD_CLOEXEC = 1;

        private const int O_APPEND = 0x400;
        private const int O_NONBLOCK = 0x800;
        private const int O_ASYNC = 0x2000;
        private const int O_DIRECT = 0x4000;
        private const int O_NOATIME = 0x40000;

        private const int FileMutableStatusMask = O_APPEND | O_NONBLOCK | O_ASYNC | O_DIRECT | O_NOATIME;
        private const int SocketMutableStatusMask = O_NONBLOCK | O_ASYNC;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            int Command = unchecked((int)Context.Arg1);
            ulong Argument = Context.Arg2;

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Descriptor);
            if (Entry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            switch (Command)
            {
                case F_DUPFD:
                    DuplicateDescriptor(Instance, Helper, Context, Descriptor, false, Argument);
                    return;
                case F_DUPFD_CLOEXEC:
                    DuplicateDescriptor(Instance, Helper, Context, Descriptor, true, Argument);
                    return;
                case F_GETFD:
                    Helper.SetReturnValue(Instance, Context, Entry.CloseOnExec ? FD_CLOEXEC : 0L);
                    return;
                case F_SETFD:
                    Entry.CloseOnExec = (Argument & FD_CLOEXEC) != 0;
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;
                case F_GETFL:
                    if (!TryGetStatusFlags(Entry.Object, out int StatusFlags))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, StatusFlags);
                    return;
                case F_SETFL:
                    if (!TrySetStatusFlags(Entry.Object, unchecked((int)Argument), out LinuxErrno Error))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)Error);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;
                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
            }
        }

        private static void DuplicateDescriptor(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong Descriptor, bool CloseOnExec, ulong MinimumDescriptor)
        {
            ulong DescriptorLimit = SocketHelpers.GetDescriptorLimit(Helper);
            if (MinimumDescriptor >= DescriptorLimit)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Helper.DescriptorTable.TryDuplicateHandle(Descriptor, MinimumDescriptor, CloseOnExec, DescriptorLimit, out ulong NewDescriptor))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                return;
            }

            Helper.SetReturnValue(Instance, Context, NewDescriptor);
        }

        private static bool TryGetStatusFlags(IFileDescriptorObject DescriptorObject, out int StatusFlags)
        {
            switch (DescriptorObject)
            {
                case FileObject FileDescriptor:
                    StatusFlags = FileDescriptor.StatusFlags;
                    return true;
                case SocketObject SocketDescriptor:
                    StatusFlags = SocketDescriptor.StatusFlags;
                    return true;
                case EventfdObject EventfdDescriptor:
                    StatusFlags = EventfdDescriptor.StatusFlags;
                    return true;
                case TimerfdObject TimerfdDescriptor:
                    StatusFlags = TimerfdDescriptor.StatusFlags;
                    return true;
                case EpollObject:
                    StatusFlags = SocketHelpers.O_RDWR;
                    return true;
                default:
                    StatusFlags = 0;
                    return false;
            }
        }

        private static bool TrySetStatusFlags(IFileDescriptorObject DescriptorObject, int RequestedFlags, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            switch (DescriptorObject)
            {
                case FileObject FileDescriptor:
                    FileDescriptor.StatusFlags = (FileDescriptor.StatusFlags & ~FileMutableStatusMask) | (RequestedFlags & FileMutableStatusMask);
                    return true;
                case SocketObject SocketDescriptor:
                    int NewStatusFlags = (SocketDescriptor.StatusFlags & ~SocketMutableStatusMask) | (RequestedFlags & SocketMutableStatusMask);
                    bool NonBlocking = (NewStatusFlags & O_NONBLOCK) != 0;

                    try
                    {
                        SocketDescriptor.Handle.Blocking = !NonBlocking;
                        SocketDescriptor.NonBlocking = NonBlocking;
                        SocketDescriptor.StatusFlags = NewStatusFlags;
                        return true;
                    }
                    catch (ObjectDisposedException)
                    {
                        Error = LinuxErrno.EBADF;
                        return false;
                    }
                    catch (System.Net.Sockets.SocketException Ex)
                    {
                        Error = SocketHelpers.TranslateSocketError(Ex.SocketErrorCode);
                        return false;
                    }
                case EventfdObject EventfdDescriptor:
                    EventfdDescriptor.StatusFlags = (EventfdDescriptor.StatusFlags & ~O_NONBLOCK) | (RequestedFlags & O_NONBLOCK);
                    EventfdDescriptor.NonBlocking = (EventfdDescriptor.StatusFlags & O_NONBLOCK) != 0;
                    return true;
                case TimerfdObject TimerfdDescriptor:
                    TimerfdDescriptor.StatusFlags = (TimerfdDescriptor.StatusFlags & ~O_NONBLOCK) | (RequestedFlags & O_NONBLOCK);
                    TimerfdDescriptor.NonBlocking = (TimerfdDescriptor.StatusFlags & O_NONBLOCK) != 0;
                    return true;
                case EpollObject:
                    return true;
                default:
                    Error = LinuxErrno.EBADF;
                    return false;
            }
        }
    }
}
