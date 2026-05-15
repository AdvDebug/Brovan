using System.Net;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Bind : ILinuxSyscall
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

            try
            {
                SocketHandle.Handle.Bind(EndPointValue);
                Helper.SetReturnValue(Instance, Context, 0L);
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
