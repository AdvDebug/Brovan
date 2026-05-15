using System.Net;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal sealed class Getsockname : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            ulong Address = Context.Arg1;
            ulong AddressLengthPointer = Context.Arg2;

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (AddressLengthPointer == 0 || !Instance.IsRegionMapped(AddressLengthPointer, 4))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (Address == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            try
            {
                EndPoint LocalEndPoint = SocketHandle.Handle.LocalEndPoint ?? GetDefaultLocalEndPoint(SocketHandle.Domain);
                if (LocalEndPoint == null)
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAFNOSUPPORT);
                    return;
                }

                if (!SocketHelpers.TryWriteSocketAddress(Instance, Address, AddressLengthPointer, LocalEndPoint, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

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

        private static EndPoint GetDefaultLocalEndPoint(int Domain)
        {
            return Domain switch
            {
                SocketHelpers.AF_INET => new IPEndPoint(IPAddress.Any, 0),
                SocketHelpers.AF_INET6 => new IPEndPoint(IPAddress.IPv6Any, 0),
                _ => null
            };
        }
    }
}
