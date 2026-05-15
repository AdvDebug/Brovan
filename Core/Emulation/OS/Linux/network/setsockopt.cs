using System;
using System.Buffers.Binary;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.network
{
    internal sealed class Setsockopt : ILinuxSyscall
    {
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong Descriptor = Context.Arg0;
            int Level = unchecked((int)Context.Arg1);
            int OptionName = unchecked((int)Context.Arg2);
            ulong OptionValueAddress = Context.Arg3;
            ulong OptionLength = Context.Arg4;

            if (!SocketHelpers.TryGetSocket(Helper, Descriptor, out SocketObject SocketHandle, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (!TryApplyOption(Instance, Context, SocketHandle, Level, OptionName, OptionValueAddress, OptionLength, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            Helper.SetReturnValue(Instance, Context, 0L);
        }

        private static bool TryApplyOption(BinaryEmulator Instance, LinuxSyscallContext Context, SocketObject SocketHandle, int Level, int OptionName, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            try
            {
                switch (Level)
                {
                    case SocketHelpers.SOL_SOCKET:
                        return TryApplySocketLevelOption(Instance, Context, SocketHandle, OptionName, OptionValueAddress, OptionLength, out Error);
                    case SocketHelpers.IPPROTO_TCP:
                        return TryApplyTcpOption(Instance, SocketHandle, OptionName, OptionValueAddress, OptionLength, out Error);
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

        private static bool TryApplySocketLevelOption(BinaryEmulator Instance, LinuxSyscallContext Context, SocketObject SocketHandle, int OptionName, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            switch (OptionName)
            {
                case SocketHelpers.SO_REUSEADDR:
                    return TrySetBooleanOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_DONTROUTE:
                    return TrySetBooleanOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.DontRoute, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_BROADCAST:
                    return TrySetBooleanOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.Broadcast, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_SNDBUF:
                    return TrySetIntOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.SendBuffer, OptionValueAddress, OptionLength, out Error, false);
                case SocketHelpers.SO_RCVBUF:
                    return TrySetIntOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, OptionValueAddress, OptionLength, out Error, false);
                case SocketHelpers.SO_KEEPALIVE:
                    return TrySetBooleanOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.KeepAlive, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_OOBINLINE:
                    return TrySetBooleanOption(Instance, SocketHandle, SocketOptionLevel.Socket, SocketOptionName.OutOfBandInline, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_REUSEPORT:
                    return TrySetReusePortOption(Instance, SocketHandle, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_RCVTIMEO_OLD:
                case SocketHelpers.SO_RCVTIMEO_NEW:
                    return TrySetTimeoutOption(Instance, Context, SocketHandle, true, OptionName, OptionValueAddress, OptionLength, out Error);
                case SocketHelpers.SO_SNDTIMEO_OLD:
                case SocketHelpers.SO_SNDTIMEO_NEW:
                    return TrySetTimeoutOption(Instance, Context, SocketHandle, false, OptionName, OptionValueAddress, OptionLength, out Error);
                default:
                    Error = LinuxErrno.ENOPROTOOPT;
                    return false;
            }
        }

        private static bool TryApplyTcpOption(BinaryEmulator Instance, SocketObject SocketHandle, int OptionName, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            switch (OptionName)
            {
                case SocketHelpers.TCP_NODELAY:
                    return TrySetTcpNoDelay(Instance, SocketHandle, OptionValueAddress, OptionLength, out Error);
                default:
                    Error = LinuxErrno.ENOPROTOOPT;
                    return false;
            }
        }

        private static bool TrySetBooleanOption(BinaryEmulator Instance, SocketObject SocketHandle, SocketOptionLevel Level, SocketOptionName OptionName, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (!TryReadInt32(Instance, OptionValueAddress, OptionLength, out int Value, out Error))
                return false;

            SocketHandle.Handle.SetSocketOption(Level, OptionName, Value != 0 ? 1 : 0);
            return true;
        }

        private static bool TrySetReusePortOption(BinaryEmulator Instance, SocketObject SocketHandle, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (!TryReadInt32(Instance, OptionValueAddress, OptionLength, out int Value, out Error))
                return false;

            SocketHandle.ReusePortEnabled = Value != 0;
            return true;
        }


        private static bool TrySetIntOption(BinaryEmulator Instance, SocketObject SocketHandle, SocketOptionLevel Level, SocketOptionName OptionName, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error, bool AllowNegative)
        {
            Error = LinuxErrno.ESUCCESS;

            if (!TryReadInt32(Instance, OptionValueAddress, OptionLength, out int Value, out Error))
                return false;

            if (!AllowNegative && Value < 0)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            SocketHandle.Handle.SetSocketOption(Level, OptionName, Value);
            return true;
        }

        private static bool TrySetTcpNoDelay(BinaryEmulator Instance, SocketObject SocketHandle, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (!TryReadInt32(Instance, OptionValueAddress, OptionLength, out int Value, out Error))
                return false;

            SocketHandle.Handle.NoDelay = Value != 0;
            return true;
        }

        private static bool TrySetTimeoutOption(BinaryEmulator Instance, LinuxSyscallContext Context, SocketObject SocketHandle, bool ReceiveTimeout, int OptionName, ulong OptionValueAddress, ulong OptionLength, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            if (!TryReadTimeoutMilliseconds(Instance, Context, OptionName, OptionValueAddress, OptionLength, out int TimeoutMilliseconds, out Error))
                return false;

            if (ReceiveTimeout)
                SocketHandle.Handle.ReceiveTimeout = TimeoutMilliseconds;
            else
                SocketHandle.Handle.SendTimeout = TimeoutMilliseconds;

            return true;
        }

        private static bool TryReadInt32(BinaryEmulator Instance, ulong Address, ulong Length, out int Value, out LinuxErrno Error)
        {
            Value = 0;
            Error = LinuxErrno.ESUCCESS;

            if (Length < 4 || Length > int.MaxValue)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            if (Address == 0 || !Instance.IsRegionMapped(Address, 4))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            Span<byte> Bytes = stackalloc byte[4];
            if (!Instance.ReadMemory(Address, Bytes))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            Value = BinaryPrimitives.ReadInt32LittleEndian(Bytes);
            return true;
        }

        private static bool TryReadTimeoutMilliseconds(BinaryEmulator Instance, LinuxSyscallContext Context, int OptionName, ulong Address, ulong Length, out int TimeoutMilliseconds, out LinuxErrno Error)
        {
            TimeoutMilliseconds = 0;
            Error = LinuxErrno.ESUCCESS;

            bool NewTimeoutLayout = OptionName == SocketHelpers.SO_RCVTIMEO_NEW || OptionName == SocketHelpers.SO_SNDTIMEO_NEW;
            int RequiredLength = NewTimeoutLayout || Context.Abi == SyscallAbi.X64 ? 16 : 8;
            if (Length < (ulong)RequiredLength || Length > int.MaxValue)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            if (Address == 0 || !Instance.IsRegionMapped(Address, (ulong)RequiredLength))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            Span<byte> Bytes = stackalloc byte[16];
            if (!Instance.ReadMemory(Address, Bytes.Slice(0, RequiredLength)))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            long Seconds;
            long Microseconds;
            if (RequiredLength == 16)
            {
                Seconds = BinaryPrimitives.ReadInt64LittleEndian(Bytes.Slice(0, 8));
                Microseconds = BinaryPrimitives.ReadInt64LittleEndian(Bytes.Slice(8, 8));
            }
            else
            {
                Seconds = BinaryPrimitives.ReadInt32LittleEndian(Bytes.Slice(0, 4));
                Microseconds = BinaryPrimitives.ReadInt32LittleEndian(Bytes.Slice(4, 4));
            }

            if (Seconds < 0 || Microseconds < 0 || Microseconds >= 1000000)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            long TotalMilliseconds = Seconds * 1000;
            if (Microseconds != 0)
                TotalMilliseconds += (Microseconds + 999) / 1000;

            if (TotalMilliseconds < 0 || TotalMilliseconds > int.MaxValue)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            TimeoutMilliseconds = (int)TotalMilliseconds;
            return true;
        }
    }
}
