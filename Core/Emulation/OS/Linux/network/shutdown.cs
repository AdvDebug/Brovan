using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Shutdown : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            int How = unchecked((int)Context.Arg1);

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            SocketShutdown Mode;
            switch (How)
            {
                case 0:
                    Mode = SocketShutdown.Receive;
                    break;
                case 1:
                    Mode = SocketShutdown.Send;
                    break;
                case 2:
                    Mode = SocketShutdown.Both;
                    break;
                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                    return;
            }

            try
            {
                SocketHandle.Handle.Shutdown(Mode);
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
