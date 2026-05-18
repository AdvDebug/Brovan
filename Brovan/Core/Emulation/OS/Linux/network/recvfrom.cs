using System;
using System.Net;
using System.Net.Sockets;
using Brovan.Core.Emulation;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal class Recvfrom : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            ulong BufferAddress = Context.Arg1;
            ulong Length = Context.Arg2;
            int Flags = unchecked((int)Context.Arg3);
            ulong SourceAddress = Context.Arg4;
            ulong SourceAddressLength = Context.Arg5;

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

            SocketFlags HostFlags = SocketHelpers.TranslateReceiveFlags(Flags, out bool PerCallNonBlocking, out Error);
            if (Error != LinuxErrno.ESUCCESS)
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if ((SocketHandle.NonBlocking || PerCallNonBlocking) && SocketHelpers.WouldBlock(SocketHandle, SelectMode.SelectRead))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            if (!SocketHelpers.TryCheckSocketRemotePolicy(Instance, SocketHandle, true, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            try
            {
                byte[] Buffer = Helper.Shared.GetBuffer(Length);
                Span<byte> Transfer = Buffer.AsSpan(0, (int)Length);
                EndPoint RemoteEndPoint = SocketHandle.Domain == SocketHelpers.AF_INET6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
                int Received = SourceAddress == 0 ? SocketHandle.Handle.Receive(Transfer, HostFlags) : SocketHandle.Handle.ReceiveFrom(Buffer, 0, (int)Length, HostFlags, ref RemoteEndPoint);

                if (SourceAddress != 0 && RemoteEndPoint != null && !SocketHelpers.TryCheckNetworkPolicy(Instance, RemoteEndPoint, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

                if (Received > 0 && !Instance.WriteMemory(BufferAddress, Transfer.Slice(0, Received)))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                if (Received > 0)
                {
                    EndPoint RemoteOverride = SourceAddress == 0 ? null : RemoteEndPoint;
                    NetworkTrafficPcapCapture.RecordInbound(SocketHandle.Handle, Transfer.Slice(0, Received), RemoteOverride);
                }

                if (SourceAddress != 0 && !SocketHelpers.TryWriteSocketAddress(Instance, SourceAddress, SourceAddressLength, RemoteEndPoint, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, (long)Received);
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