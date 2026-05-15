using System.Net;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Connect : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            ulong Address = Context.Arg1;
            ulong AddressLength = Context.Arg2;

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (!SocketHelpers.TryReadSocketAddress(Instance, Address, AddressLength, out EndPoint EndPointValue, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (!SocketHelpers.TryCheckNetworkPolicy(Instance, EndPointValue, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (SocketHandle.PendingConnect != null)
            {
                if (!SocketHandle.PendingConnectCompleted)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EALREADY);
                    return;
                }

                SocketError PendingError = SocketHandle.PendingConnect.SocketError;
                SocketHandle.PendingConnect.Dispose();
                SocketHandle.PendingConnect = null;
                SocketHandle.PendingConnectCompleted = false;

                Helper.SetReturnValue(Instance, Context, PendingError == SocketError.Success ? -(long)LinuxErrno.EISCONN : -(long)TranslateConnectError(PendingError, SocketHandle.NonBlocking));
                return;
            }

            try
            {
                if (SocketHandle.NonBlocking)
                {
                    SocketAsyncEventArgs Args = new SocketAsyncEventArgs();
                    Args.RemoteEndPoint = EndPointValue;
                    Args.Completed += (Sender, CompletedArgs) => SocketHandle.PendingConnectCompleted = true;

                    bool Pending = SocketHandle.Handle.ConnectAsync(Args);
                    if (Pending)
                    {
                        SocketHandle.PendingConnect = Args;
                        SocketHandle.PendingConnectCompleted = false;
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINPROGRESS);
                        return;
                    }

                    SocketError ErrorCode = Args.SocketError;
                    Args.Dispose();
                    Helper.SetReturnValue(Instance, Context, ErrorCode == SocketError.Success ? 0L : -(long)TranslateConnectError(ErrorCode, true));
                    return;
                }

                SocketHandle.Handle.Connect(EndPointValue);
                Helper.SetReturnValue(Instance, Context, 0L);
            }
            catch (SocketException Ex)
            {
                Helper.SetReturnValue(Instance, Context, -(long)TranslateConnectError(Ex.SocketErrorCode, SocketHandle.NonBlocking));
            }
            catch (ObjectDisposedException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
            }
            catch (InvalidOperationException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EALREADY);
            }
        }

        private static LinuxErrno TranslateConnectError(SocketError Error, bool NonBlocking)
        {
            if (NonBlocking && (Error == SocketError.WouldBlock || Error == SocketError.InProgress || Error == SocketError.TryAgain))
                return LinuxErrno.EINPROGRESS;

            return SocketHelpers.TranslateSocketError(Error);
        }
    }
}
