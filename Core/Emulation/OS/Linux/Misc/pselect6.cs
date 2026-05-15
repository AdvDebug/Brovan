using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;

namespace Brovan.Core.Emulation.OS.Linux.Misc
{
    internal sealed class Pselect6 : ILinuxSyscall
    {
        private const long NanosecondsPerSecond = 1000000000L;

        private byte[] _sourceRead = Array.Empty<byte>();
        private byte[] _sourceWrite = Array.Empty<byte>();
        private byte[] _sourceExcept = Array.Empty<byte>();
        private byte[] _readyRead = Array.Empty<byte>();
        private byte[] _readyWrite = Array.Empty<byte>();
        private byte[] _readyExcept = Array.Empty<byte>();

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            long Nfds = GetSignedNfds(Context);
            ulong ReadFds = Context.Arg1;
            ulong WriteFds = Context.Arg2;
            ulong ExceptFds = Context.Arg3;
            ulong TimeoutAddress = Context.Arg4;
            ulong SigmaskDataAddress = Context.Arg5;

            if (Nfds < 0 || (ulong)Nfds > SocketHelpers.GetDescriptorLimit(Helper))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            int WordSize = Context.Abi == SyscallAbi.X64 ? 8 : 4;
            ulong SetBytes = GetSetByteCount((ulong)Nfds, WordSize);
            if (SetBytes > int.MaxValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOMEM);
                return;
            }

            if (!TryValidateFdSet(Instance, ReadFds, SetBytes)
                || !TryValidateFdSet(Instance, WriteFds, SetBytes)
                || !TryValidateFdSet(Instance, ExceptFds, SetBytes))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (!TryReadTimeout(Instance, Context, TimeoutAddress, out TimeSpan? Timeout, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (!TryValidateSigmaskData(Instance, Context, SigmaskDataAddress, out Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            int SetLength = (int)SetBytes;
            EnsureCapacity(ref _sourceRead, SetLength);
            EnsureCapacity(ref _sourceWrite, SetLength);
            EnsureCapacity(ref _sourceExcept, SetLength);
            EnsureCapacity(ref _readyRead, SetLength);
            EnsureCapacity(ref _readyWrite, SetLength);
            EnsureCapacity(ref _readyExcept, SetLength);

            if (!TryReadFdSet(Instance, ReadFds, SetBytes, _sourceRead)
                || !TryReadFdSet(Instance, WriteFds, SetBytes, _sourceWrite)
                || !TryReadFdSet(Instance, ExceptFds, SetBytes, _sourceExcept))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            Stopwatch Timer = Stopwatch.StartNew();
            while (true)
            {
                if (!TryBuildReadySets(Helper, (int)Nfds, _sourceRead, _sourceWrite, _sourceExcept, _readyRead, _readyWrite, _readyExcept, out int ReadyCount, out Error))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)Error);
                    return;
                }

                if (ReadyCount != 0 || Timeout == TimeSpan.Zero || (Timeout.HasValue && Timer.Elapsed >= Timeout.Value))
                {
                    if (!WriteFdSet(Instance, ReadFds, _readyRead)
                        || !WriteFdSet(Instance, WriteFds, _readyWrite)
                        || !WriteFdSet(Instance, ExceptFds, _readyExcept)
                        || !WriteRemainingTimeout(Instance, Context, TimeoutAddress, Timeout, Timer.Elapsed))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, ReadyCount);
                    return;
                }

                SleepUntilNextPoll(Timeout, Timer.Elapsed);
            }
        }

        private static void EnsureCapacity(ref byte[] Buffer, int Size)
        {
            if (Buffer.Length >= Size)
                return;

            int NewSize = Buffer.Length == 0 ? 0x1000 : Buffer.Length;
            while (NewSize < Size)
                NewSize *= 2;

            Array.Resize(ref Buffer, NewSize);
        }

        private static bool TryReadFdSet(BinaryEmulator Instance, ulong Address, ulong Length, byte[] Buffer)
        {
            if (Address == 0 || Length == 0)
                return true;

            return Instance.ReadMemory(Address, Buffer.AsSpan(0, (int)Length));
        }

        private static long GetSignedNfds(LinuxSyscallContext Context)
        {
            if (Context.Abi == SyscallAbi.X64)
                return unchecked((long)Context.Arg0);

            return unchecked((int)(uint)Context.Arg0);
        }

        private static ulong GetSetByteCount(ulong Nfds, int WordSize)
        {
            ulong BitsPerWord = (ulong)(WordSize * 8);
            ulong Words = (Nfds + BitsPerWord - 1) / BitsPerWord;
            return Words * (ulong)WordSize;
        }

        private static bool TryValidateFdSet(BinaryEmulator Instance, ulong Address, ulong Length)
        {
            return Address == 0 || Length == 0 || Instance.IsRegionMapped(Address, Length);
        }

        private static bool TryReadTimeout(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, out TimeSpan? Timeout, out LinuxErrno Error)
        {
            Timeout = null;
            Error = LinuxErrno.ESUCCESS;

            if (Address == 0)
                return true;

            int Length = Context.Abi == SyscallAbi.X64 ? 16 : 8;
            if (!Instance.IsRegionMapped(Address, (ulong)Length))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            Span<byte> Buffer = stackalloc byte[16];
            if (!Instance.ReadMemory(Address, Buffer.Slice(0, Length)))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            long Seconds;
            long Nanoseconds;
            if (Context.Abi == SyscallAbi.X64)
            {
                Seconds = BinaryPrimitives.ReadInt64LittleEndian(Buffer.Slice(0, 8));
                Nanoseconds = BinaryPrimitives.ReadInt64LittleEndian(Buffer.Slice(8, 8));
            }
            else
            {
                Seconds = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0, 4));
                Nanoseconds = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(4, 4));
            }

            if (Seconds < 0 || Nanoseconds < 0 || Nanoseconds >= NanosecondsPerSecond)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }

            double TotalMilliseconds = Seconds * 1000.0 + Nanoseconds / 1000000.0;
            if (TotalMilliseconds > int.MaxValue)
                Timeout = TimeSpan.FromMilliseconds(int.MaxValue);
            else
                Timeout = TimeSpan.FromMilliseconds(TotalMilliseconds);

            return true;
        }

        private static bool TryValidateSigmaskData(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;
            if (Address == 0)
                return true;

            int WordSize = Context.Abi == SyscallAbi.X64 ? 8 : 4;
            ulong DataSize = (ulong)(WordSize * 2);
            if (!Instance.IsRegionMapped(Address, DataSize))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            Span<byte> Buffer = stackalloc byte[16];
            if (!Instance.ReadMemory(Address, Buffer.Slice(0, (int)DataSize)))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            ulong SigsetAddress = ReadWord(Buffer, 0, WordSize);
            ulong SigsetSize = ReadWord(Buffer, WordSize, WordSize);
            if (SigsetAddress == 0 || SigsetSize == 0)
                return true;

            if (SigsetSize > int.MaxValue || !Instance.IsRegionMapped(SigsetAddress, SigsetSize))
            {
                Error = LinuxErrno.EFAULT;
                return false;
            }

            return true;
        }

        private static ulong ReadWord(ReadOnlySpan<byte> Buffer, int Offset, int WordSize)
        {
            return WordSize == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(Buffer.Slice(Offset, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(Offset, 4));
        }

        private static bool TryBuildReadySets(LinuxSyscallsHelper Helper, int Nfds, byte[] SourceRead, byte[] SourceWrite, byte[] SourceExcept, byte[] ReadyRead, byte[] ReadyWrite, byte[] ReadyExcept, out int ReadyCount, out LinuxErrno Error)
        {
            Array.Clear(ReadyRead, 0, ReadyRead.Length);
            Array.Clear(ReadyWrite, 0, ReadyWrite.Length);
            Array.Clear(ReadyExcept, 0, ReadyExcept.Length);
            ReadyCount = 0;
            Error = LinuxErrno.ESUCCESS;

            for (int Descriptor = 0; Descriptor < Nfds; Descriptor++)
            {
                bool WantRead = IsSet(SourceRead, Descriptor);
                bool WantWrite = IsSet(SourceWrite, Descriptor);
                bool WantExcept = IsSet(SourceExcept, Descriptor);
                if (!WantRead && !WantWrite && !WantExcept)
                    continue;

                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry((ulong)Descriptor);
                if (Entry == null)
                {
                    Error = LinuxErrno.EBADF;
                    return false;
                }

                if (WantRead && IsReady(Helper, Entry.Object, SelectMode.SelectRead))
                {
                    SetBit(ReadyRead, Descriptor);
                    ReadyCount++;
                }

                if (WantWrite && IsReady(Helper, Entry.Object, SelectMode.SelectWrite))
                {
                    SetBit(ReadyWrite, Descriptor);
                    ReadyCount++;
                }

                if (WantExcept && IsReady(Helper, Entry.Object, SelectMode.SelectError))
                {
                    SetBit(ReadyExcept, Descriptor);
                    ReadyCount++;
                }
            }

            return true;
        }

        private static bool IsReady(LinuxSyscallsHelper Helper, IFileDescriptorObject Object, SelectMode Mode)
        {
            switch (Object)
            {
                case FileObject:
                    return true;
                case SocketObject SocketDescriptor:
                    return IsSocketReady(SocketDescriptor, Mode);
                case EventfdObject EventfdDescriptor:
                    if (Mode == SelectMode.SelectRead)
                        return EventfdDescriptor.Counter > 0;
                    if (Mode == SelectMode.SelectWrite)
                        return EventfdDescriptor.Counter < EventfdObject.MaxCounterValue;
                    return false;
                case TimerfdObject TimerfdDescriptor:
                    if (Mode != SelectMode.SelectRead)
                        return false;

                    TimerfdDescriptor.Update(LinuxEventHelpers.GetClockNanoseconds(Helper, TimerfdDescriptor.ClockId));
                    return TimerfdDescriptor.PendingExpirations != 0;
                case EpollObject EpollDescriptor:
                    if (Mode != SelectMode.SelectRead)
                        return false;

                    foreach (var Pair in EpollDescriptor.Interests)
                    {
                        FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Pair.Key);
                        if (Entry == null || Pair.Value.Disabled)
                            continue;

                        if (LinuxEventHelpers.GetReadyEvents(null, Helper, Entry.Object, Pair.Value.Events) != 0)
                            return true;
                    }

                    return false;
                default:
                    return false;
            }
        }

        private static bool IsSocketReady(SocketObject SocketDescriptor, SelectMode Mode)
        {
            if (SocketDescriptor.PendingConnect != null)
            {
                if (!SocketDescriptor.PendingConnectCompleted)
                    return false;

                return Mode == SelectMode.SelectWrite || Mode == SelectMode.SelectError;
            }

            try
            {
                return SocketDescriptor.Handle.Poll(0, Mode);
            }
            catch
            {
                return true;
            }
        }

        private static bool IsSet(byte[] Buffer, int Bit)
        {
            int ByteIndex = Bit >> 3;
            if (ByteIndex < 0 || ByteIndex >= Buffer.Length)
                return false;

            return (Buffer[ByteIndex] & (1 << (Bit & 7))) != 0;
        }

        private static void SetBit(byte[] Buffer, int Bit)
        {
            int ByteIndex = Bit >> 3;
            if (ByteIndex < 0 || ByteIndex >= Buffer.Length)
                return;

            Buffer[ByteIndex] |= (byte)(1 << (Bit & 7));
        }

        private static bool WriteFdSet(BinaryEmulator Instance, ulong Address, byte[] Buffer)
        {
            if (Address == 0 || Buffer.Length == 0)
                return true;

            return Instance.WriteMemory(Address, Buffer);
        }

        private static bool WriteRemainingTimeout(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address, TimeSpan? Timeout, TimeSpan Elapsed)
        {
            if (Address == 0 || !Timeout.HasValue)
                return true;

            TimeSpan Remaining = Timeout.Value - Elapsed;
            if (Remaining < TimeSpan.Zero)
                Remaining = TimeSpan.Zero;

            long Seconds = (long)Remaining.TotalSeconds;
            long Nanoseconds = (long)((Remaining - TimeSpan.FromSeconds(Seconds)).Ticks * 100L);
            if (Context.Abi == SyscallAbi.X64)
            {
                Span<byte> Buffer = stackalloc byte[16];
                BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0, 8), Seconds);
                BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(8, 8), Nanoseconds);
                return Instance.WriteMemory(Address, Buffer);
            }
            else
            {
                Span<byte> Buffer = stackalloc byte[8];
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0, 4), unchecked((int)Seconds));
                BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4, 4), unchecked((int)Nanoseconds));
                return Instance.WriteMemory(Address, Buffer);
            }
        }

        private static void SleepUntilNextPoll(TimeSpan? Timeout, TimeSpan Elapsed)
        {
            if (!Timeout.HasValue)
            {
                Thread.Sleep(1);
                return;
            }

            TimeSpan Remaining = Timeout.Value - Elapsed;
            if (Remaining <= TimeSpan.Zero)
                return;

            int SleepMilliseconds = Math.Max(1, Math.Min(10, (int)Math.Ceiling(Remaining.TotalMilliseconds)));
            Thread.Sleep(SleepMilliseconds);
        }
    }
}
