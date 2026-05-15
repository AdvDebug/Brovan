using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Socketcall : ILinuxSyscall
    {
        private const int SYS_SOCKET = 1;
        private const int SYS_BIND = 2;
        private const int SYS_CONNECT = 3;
        private const int SYS_LISTEN = 4;
        private const int SYS_ACCEPT = 5;
        private const int SYS_GETSOCKNAME = 6;
        private const int SYS_SEND = 9;
        private const int SYS_RECV = 10;
        private const int SYS_SENDTO = 11;
        private const int SYS_RECVFROM = 12;
        private const int SYS_SHUTDOWN = 13;
        private const int SYS_SETSOCKOPT = 14;
        private const int SYS_GETSOCKOPT = 15;

        private static readonly Socket SocketSyscall = new Socket();
        private static readonly Bind BindSyscall = new Bind();
        private static readonly Connect ConnectSyscall = new Connect();
        private static readonly Listen ListenSyscall = new Listen();
        private static readonly Accept AcceptSyscall = new Accept();
        private static readonly Getsockname GetsocknameSyscall = new Getsockname();
        private static readonly Sendto SendtoSyscall = new Sendto();
        private static readonly Recvfrom RecvfromSyscall = new Recvfrom();
        private static readonly Shutdown ShutdownSyscall = new Shutdown();
        private static readonly Setsockopt SetsockoptSyscall = new Setsockopt();
        private static readonly Getsockopt GetsockoptSyscall = new Getsockopt();

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            int Call = unchecked((int)Context.Arg0);
            ulong ArgumentsPointer = Context.Arg1;
            if (ArgumentsPointer == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            int ArgumentCount = GetArgumentCount(Call);
            if (ArgumentCount == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOSYS);
                return;
            }

            ulong ArgumentBytes = (ulong)(ArgumentCount * 4);
            if (!Instance.IsRegionMapped(ArgumentsPointer, ArgumentBytes))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> RawArguments = stackalloc byte[24];
            RawArguments.Clear();
            if (!Instance.ReadMemory(ArgumentsPointer, RawArguments.Slice(0, (int)ArgumentBytes)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            LinuxSyscallContext CallContext = new LinuxSyscallContext()
            {
                Abi = Context.Abi,
                Arg0 = BinaryPrimitives.ReadUInt32LittleEndian(RawArguments.Slice(0, 4)),
                Arg1 = BinaryPrimitives.ReadUInt32LittleEndian(RawArguments.Slice(4, 4)),
                Arg2 = BinaryPrimitives.ReadUInt32LittleEndian(RawArguments.Slice(8, 4)),
                Arg3 = BinaryPrimitives.ReadUInt32LittleEndian(RawArguments.Slice(12, 4)),
                Arg4 = BinaryPrimitives.ReadUInt32LittleEndian(RawArguments.Slice(16, 4)),
                Arg5 = BinaryPrimitives.ReadUInt32LittleEndian(RawArguments.Slice(20, 4))
            };

            switch (Call)
            {
                case SYS_SOCKET:
                    SocketSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_BIND:
                    BindSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_CONNECT:
                    ConnectSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_LISTEN:
                    ListenSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_ACCEPT:
                    AcceptSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_GETSOCKNAME:
                    GetsocknameSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_SEND:
                    CallContext.Arg4 = 0;
                    CallContext.Arg5 = 0;
                    SendtoSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_RECV:
                    CallContext.Arg4 = 0;
                    CallContext.Arg5 = 0;
                    RecvfromSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_SENDTO:
                    SendtoSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_RECVFROM:
                    RecvfromSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_SHUTDOWN:
                    ShutdownSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_SETSOCKOPT:
                    SetsockoptSyscall.Handle(Instance, Helper, CallContext);
                    return;
                case SYS_GETSOCKOPT:
                    GetsockoptSyscall.Handle(Instance, Helper, CallContext);
                    return;
                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOSYS);
                    return;
            }
        }

        private static int GetArgumentCount(int Call)
        {
            return Call switch
            {
                SYS_SOCKET => 3,
                SYS_BIND => 3,
                SYS_CONNECT => 3,
                SYS_LISTEN => 2,
                SYS_ACCEPT => 3,
                SYS_GETSOCKNAME => 3,
                SYS_SEND => 4,
                SYS_RECV => 4,
                SYS_SENDTO => 6,
                SYS_RECVFROM => 6,
                SYS_SHUTDOWN => 2,
                SYS_SETSOCKOPT => 5,
                SYS_GETSOCKOPT => 5,
                _ => 0
            };
        }
    }
}
