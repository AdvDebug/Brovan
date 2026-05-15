using System;
using System.Buffers.Binary;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal sealed class Getsockopt : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            int Level = unchecked((int)Context.Arg1);
            int OptionName = unchecked((int)Context.Arg2);
            ulong OptionValueAddress = Context.Arg3;
            ulong OptionLengthAddress = Context.Arg4;

            if (OptionLengthAddress == 0 || !Instance.IsRegionMapped(OptionLengthAddress, 4))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Span<byte> LengthBuffer = stackalloc byte[4];
            if (!Instance.ReadMemory(OptionLengthAddress, LengthBuffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            uint RequestedLength = BinaryPrimitives.ReadUInt32LittleEndian(LengthBuffer);
            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            Span<byte> Value = stackalloc byte[16];
            if (!TryBuildOption(Instance, Context, SocketHandle, Level, OptionName, Value, out int ValueLength, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            uint CopyLength = Math.Min(RequestedLength, (uint)ValueLength);
            if (CopyLength != 0)
            {
                if (OptionValueAddress == 0 || !Instance.IsRegionMapped(OptionValueAddress, CopyLength))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                if (!Instance.WriteMemory(OptionValueAddress, Value.Slice(0, (int)CopyLength)))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }
            }
            else if (RequestedLength != 0 && ValueLength != 0 && OptionValueAddress == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(LengthBuffer, (uint)ValueLength);
            if (!Instance.WriteMemory(OptionLengthAddress, LengthBuffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static bool TryBuildOption(BinaryEmulator Instance, LinuxSyscallContext Context, SocketObject SocketHandle, int Level, int OptionName, Span<byte> Value, out int ValueLength, out LinuxErrno Error)
        {
            ValueLength = 0;
            Error = LinuxErrno.ESUCCESS;

            try
            {
                switch (Level)
                {
                    case SocketHelpers.SOL_SOCKET:
                        return TryBuildSocketLevelOption(Context, SocketHandle, OptionName, Value, out ValueLength, out Error);
                    case SocketHelpers.IPPROTO_TCP:
                        return TryBuildTcpOption(SocketHandle, OptionName, Value, out ValueLength, out Error);
                    default:
                        Error = LinuxErrno.ENOPROTOOPT;
                        return false;
                }
            }
            catch (ObjectDisposedException)
            {
                Error = LinuxErrno.EBADF;
                return false;
            }
            catch (SocketException Ex)
            {
                Error = SocketHelpers.TranslateSocketError(Ex.SocketErrorCode);
                return false;
            }
            catch (ArgumentException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                Error = LinuxErrno.ENOPROTOOPT;
                return false;
            }
        }

        private static bool TryBuildSocketLevelOption(LinuxSyscallContext Context, SocketObject SocketHandle, int OptionName, Span<byte> Value, out int ValueLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;
            ValueLength = 0;

            switch (OptionName)
            {
                case SocketHelpers.SO_TYPE:
                    ValueLength = BuildInt32(Value, SocketHandle.Type);
                    return true;
                case SocketHelpers.SO_ERROR:
                    ValueLength = BuildInt32(Value, ConsumeSocketError(SocketHandle));
                    return true;
                case SocketHelpers.SO_DONTROUTE:
                    return TryBuildHostBooleanOption(SocketHandle, SocketOptionLevel.Socket, SocketOptionName.DontRoute, Value, out ValueLength, out Error);
                case SocketHelpers.SO_BROADCAST:
                    return TryBuildHostBooleanOption(SocketHandle, SocketOptionLevel.Socket, SocketOptionName.Broadcast, Value, out ValueLength, out Error);
                case SocketHelpers.SO_REUSEADDR:
                    return TryBuildHostBooleanOption(SocketHandle, SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, Value, out ValueLength, out Error);
                case SocketHelpers.SO_KEEPALIVE:
                    return TryBuildHostBooleanOption(SocketHandle, SocketOptionLevel.Socket, SocketOptionName.KeepAlive, Value, out ValueLength, out Error);
                case SocketHelpers.SO_OOBINLINE:
                    return TryBuildHostBooleanOption(SocketHandle, SocketOptionLevel.Socket, SocketOptionName.OutOfBandInline, Value, out ValueLength, out Error);
                case SocketHelpers.SO_SNDBUF:
                    ValueLength = BuildInt32(Value, SocketHandle.Handle.SendBufferSize);
                    return true;
                case SocketHelpers.SO_RCVBUF:
                    ValueLength = BuildInt32(Value, SocketHandle.Handle.ReceiveBufferSize);
                    return true;
                case SocketHelpers.SO_LINGER:
                    ValueLength = BuildLinger(Value, SocketHandle.Handle.LingerState);
                    return true;
                case SocketHelpers.SO_REUSEPORT:
                    ValueLength = BuildInt32(Value, SocketHandle.ReusePortEnabled ? 1 : 0);
                    return true;
                case SocketHelpers.SO_RCVLOWAT:
                case SocketHelpers.SO_SNDLOWAT:
                    ValueLength = BuildInt32(Value, 1);
                    return true;
                case SocketHelpers.SO_ACCEPTCONN:
                    ValueLength = BuildInt32(Value, SocketHandle.IsListening ? 1 : 0);
                    return true;
                case SocketHelpers.SO_PROTOCOL:
                    ValueLength = BuildInt32(Value, GetProtocol(SocketHandle));
                    return true;
                case SocketHelpers.SO_DOMAIN:
                    ValueLength = BuildInt32(Value, SocketHandle.Domain);
                    return true;
                case SocketHelpers.SO_RCVTIMEO_OLD:
                case SocketHelpers.SO_RCVTIMEO_NEW:
                    ValueLength = BuildTimeval(Value, SocketHandle.Handle.ReceiveTimeout, Context, OptionName);
                    return true;
                case SocketHelpers.SO_SNDTIMEO_OLD:
                case SocketHelpers.SO_SNDTIMEO_NEW:
                    ValueLength = BuildTimeval(Value, SocketHandle.Handle.SendTimeout, Context, OptionName);
                    return true;
                default:
                    Error = LinuxErrno.ENOPROTOOPT;
                    return false;
            }
        }

        private static bool TryBuildTcpOption(SocketObject SocketHandle, int OptionName, Span<byte> Value, out int ValueLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;
            ValueLength = 0;

            switch (OptionName)
            {
                case SocketHelpers.TCP_NODELAY:
                    ValueLength = BuildInt32(Value, SocketHandle.Handle.NoDelay ? 1 : 0);
                    return true;
                default:
                    Error = LinuxErrno.ENOPROTOOPT;
                    return false;
            }
        }

        private static bool TryBuildHostBooleanOption(SocketObject SocketHandle, SocketOptionLevel Level, SocketOptionName OptionName, Span<byte> Value, out int ValueLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;
            object Result = SocketHandle.Handle.GetSocketOption(Level, OptionName);
            ValueLength = BuildInt32(Value, Convert.ToInt32(Result) != 0 ? 1 : 0);
            return true;
        }

        private static int ConsumeSocketError(SocketObject SocketHandle)
        {
            if (SocketHandle.PendingConnect != null)
            {
                if (!SocketHandle.PendingConnectCompleted)
                    return (int)LinuxErrno.EINPROGRESS;

                SocketError PendingError = SocketHandle.PendingConnect.SocketError;
                SocketHandle.PendingConnect.Dispose();
                SocketHandle.PendingConnect = null;
                SocketHandle.PendingConnectCompleted = false;
                return PendingError == SocketError.Success ? 0 : (int)SocketHelpers.TranslateSocketError(PendingError);
            }

            object Result = SocketHandle.Handle.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
            SocketError Error = (SocketError)Convert.ToInt32(Result);
            return Error == SocketError.Success ? 0 : (int)SocketHelpers.TranslateSocketError(Error);
        }

        private static int GetProtocol(SocketObject SocketHandle)
        {
            if (SocketHandle.Protocol != 0)
                return SocketHandle.Protocol;

            return SocketHandle.Type switch
            {
                SocketHelpers.SOCK_STREAM => SocketHelpers.IPPROTO_TCP,
                SocketHelpers.SOCK_DGRAM => SocketHelpers.IPPROTO_UDP,
                _ => 0
            };
        }

        private static int BuildInt32(Span<byte> Value, int Data)
        {
            BinaryPrimitives.WriteInt32LittleEndian(Value.Slice(0, 4), Data);
            return 4;
        }

        private static int BuildLinger(Span<byte> Value, LingerOption Option)
        {
            BinaryPrimitives.WriteInt32LittleEndian(Value.Slice(0, 4), Option != null && Option.Enabled ? 1 : 0);
            BinaryPrimitives.WriteInt32LittleEndian(Value.Slice(4, 4), Option?.LingerTime ?? 0);
            return 8;
        }

        private static int BuildTimeval(Span<byte> Value, int TimeoutMilliseconds, LinuxSyscallContext Context, int OptionName)
        {
            if (TimeoutMilliseconds < 0)
                TimeoutMilliseconds = 0;

            long Seconds = TimeoutMilliseconds / 1000;
            long Microseconds = (TimeoutMilliseconds % 1000) * 1000L;
            bool LongLayout = Context.Abi == SyscallAbi.X64 || OptionName == SocketHelpers.SO_RCVTIMEO_NEW || OptionName == SocketHelpers.SO_SNDTIMEO_NEW;

            if (LongLayout)
            {
                BinaryPrimitives.WriteInt64LittleEndian(Value.Slice(0, 8), Seconds);
                BinaryPrimitives.WriteInt64LittleEndian(Value.Slice(8, 8), Microseconds);
                return 16;
            }

            BinaryPrimitives.WriteInt32LittleEndian(Value.Slice(0, 4), unchecked((int)Seconds));
            BinaryPrimitives.WriteInt32LittleEndian(Value.Slice(4, 4), unchecked((int)Microseconds));
            return 8;
        }
    }
}
