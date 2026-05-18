using System;
using System.Net;
using System.Net.Sockets;
using Brovan.Core.Emulation;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Sendto : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            ulong BufferAddress = Context.Arg1;
            ulong Length = Context.Arg2;
            int Flags = unchecked((int)Context.Arg3);
            ulong DestinationAddress = Context.Arg4;
            ulong DestinationLength = Context.Arg5;

            if (Length == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (Length > int.MaxValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.IsRegionMapped(BufferAddress, Length))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            SocketFlags HostFlags = SocketHelpers.TranslateSendFlags(Flags, out bool PerCallNonBlocking, out Error);
            if (Error != LinuxErrno.ESUCCESS)
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if ((SocketHandle.NonBlocking || PerCallNonBlocking) && SocketHelpers.WouldBlock(SocketHandle, SelectMode.SelectWrite))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            EndPoint Destination = null;
            if (DestinationAddress == 0 && !SocketHelpers.TryCheckSocketRemotePolicy(Instance, SocketHandle, true, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (DestinationAddress != 0)
            {
                if (!SocketHelpers.TryReadSocketAddress(Instance, DestinationAddress, DestinationLength, out Destination, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

                if (!SocketHelpers.TryCheckNetworkPolicy(Instance, Destination, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }
            }

            try
            {
                byte[] Buffer = Helper.Shared.GetBuffer(Length);
                Span<byte> Transfer = Buffer.AsSpan(0, (int)Length);
                if (!Instance.ReadMemory(BufferAddress, Transfer))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                int Sent = Destination == null ? SocketHandle.Handle.Send(Transfer, HostFlags) : SocketHandle.Handle.SendTo(Buffer, 0, (int)Length, HostFlags, Destination);
                if (Sent > 0)
                    NetworkTrafficPcapCapture.RecordOutbound(SocketHandle.Handle, Buffer.AsSpan(0, Sent), Destination);

                Helper.SetReturnValue(Instance, Context, (long)Sent);
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