using System.Net;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Listen : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            int Backlog = unchecked((int)Context.Arg1);

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (!SocketHelpers.TryCheckNetworkPolicy(Instance, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (Instance.Settings.GetNetworkPolicy().Mode != NetworkAccessMode.Full)
            {
                if (SocketHandle.Handle.LocalEndPoint is not IPEndPoint LocalEndPoint || !SocketHelpers.TryCheckNetworkPolicy(Instance, LocalEndPoint, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENETUNREACH);
                    return;
                }
            }

            try
            {
                SocketHandle.Handle.Listen(Math.Max(Backlog, 0));
                SocketHandle.IsListening = true;
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
