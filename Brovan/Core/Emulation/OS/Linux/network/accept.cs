using System.Net;
using System.Net.Sockets;
using HostSocket = System.Net.Sockets.Socket;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Accept : ILinuxSyscall
    {
        private readonly bool Accept4;

        public Accept(bool Accept4 = false)
        {
            this.Accept4 = Accept4;
        }

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            ulong Address = Context.Arg1;
            ulong AddressLengthPointer = Context.Arg2;
            int Flags = Accept4 ? unchecked((int)Context.Arg3) : 0;

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (Accept4)
            {
                int UnsupportedFlags = Flags & ~(SocketHelpers.SOCK_NONBLOCK | SocketHelpers.SOCK_CLOEXEC);
                if (UnsupportedFlags != 0)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
                }
            }

            if (SocketHandle.NonBlocking && SocketHelpers.WouldBlock(SocketHandle, SelectMode.SelectRead))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            if (!SocketHelpers.TryCheckNetworkPolicy(Instance, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            try
            {
                BrovanSocket Accepted = SocketHandle.Handle.Accept();
                EndPoint RemoteEndPoint = null;
                try
                {
                    RemoteEndPoint = Accepted.RemoteEndPoint;
                }
                catch (SocketException)
                {
                }

                if (RemoteEndPoint == null && Instance.Settings.GetNetworkPolicy().Mode != NetworkAccessMode.Full)
                {
                    try { Accepted.Dispose(); } catch { }
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENETUNREACH);
                    return;
                }

                if (RemoteEndPoint != null && !SocketHelpers.TryCheckNetworkPolicy(Instance, RemoteEndPoint, out Error))
                {
                    try { Accepted.Dispose(); } catch { }
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

                bool AcceptedNonBlocking = Accept4 && (Flags & SocketHelpers.SOCK_NONBLOCK) != 0;
                bool CloseOnExec = Accept4 && (Flags & SocketHelpers.SOCK_CLOEXEC) != 0;
                Accepted.Blocking = !AcceptedNonBlocking;

                int AcceptedStatusFlags = SocketHelpers.O_RDWR | (AcceptedNonBlocking ? SocketHelpers.O_NONBLOCK : 0);
                SocketObject AcceptedObject = new SocketObject(Accepted, SocketHandle.Domain, SocketHandle.Type, SocketHandle.Protocol, AcceptedStatusFlags, AcceptedNonBlocking);
                ulong DescriptorLimit = SocketHelpers.GetDescriptorLimit(Helper);
                if (!Helper.DescriptorTable.TryAddHandle(AcceptedObject, CloseOnExec, DescriptorLimit, out ulong AcceptedDescriptor))
                {
                    AcceptedObject.Dispose();
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                    return;
                }

                if ((Address != 0 || AddressLengthPointer != 0) && !SocketHelpers.TryWriteSocketAddress(Instance, Address, AddressLengthPointer, Accepted.RemoteEndPoint, out Error))
                {
                    Helper.DescriptorTable.CloseHandle(AcceptedDescriptor);
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, AcceptedDescriptor);
            }
            catch (SocketException Ex)
            {
                Helper.SetReturnValue(Instance, Context, -(long)SocketHelpers.TranslateSocketError(Ex.SocketErrorCode));
            }
            catch (ObjectDisposedException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
            }
        }
    }
}
