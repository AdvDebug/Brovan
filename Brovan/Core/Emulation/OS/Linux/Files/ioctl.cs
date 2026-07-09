using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Ioctl : ILinuxSyscall
    {
        private const int SIGWINCH = 28;
        private const int TermiosSize = 36;
        private const int WinsizeSize = 8;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            uint request = unchecked((uint)Context.Arg1);
            ulong argp = Context.Arg2;

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (Entry.Object is not FileObject FileDesc || FileDesc.TerminalState == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTTY);
                return;
            }

            LinuxTerminalState TerminalState = FileDesc.TerminalState;
            switch ((LinuxIoctlRequest)request)
            {
                case LinuxIoctlRequest.TCGETS:
                    if (!WriteBytesToGuest(Instance, Helper, Context, argp, TerminalState.Termios))
                        return;
                    Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                    return;

                case LinuxIoctlRequest.TCSETS:
                case LinuxIoctlRequest.TCSETSW:
                case LinuxIoctlRequest.TCSETSF:
                    if (!ReadBytesFromGuest(Instance, Helper, Context, argp, TerminalState.Termios))
                        return;
                    Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                    return;

                case LinuxIoctlRequest.TIOCGWINSZ:
                    if (!WriteWinsizeToGuest(Instance, Helper, Context, argp, TerminalState))
                        return;
                    Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                    return;

                case LinuxIoctlRequest.TIOCSWINSZ:
                    if (!ReadWinsizeFromGuest(Instance, Helper, Context, argp, TerminalState, out bool Changed))
                        return;

                    if (Changed)
                        QueueSigwinch(Instance, Helper);

                    Helper.SetReturnValue(Instance, Context, LinuxErrno.ESUCCESS);
                    return;

                default:
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTTY);
                    return;
            }
        }

        private static bool WriteBytesToGuest(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong Address, byte[] Data)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, (ulong)Data.Length))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            if (!Instance.WriteMemory(Address, Data))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            return true;
        }

        private static bool ReadBytesFromGuest(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong Address, byte[] Destination)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, (ulong)Destination.Length))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            Span<byte> Buffer = stackalloc byte[Destination.Length];
            if (!Instance.ReadMemory(Address, Buffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            Buffer.CopyTo(Destination);
            return true;
        }

        private static bool WriteWinsizeToGuest(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong Address, LinuxTerminalState TerminalState)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, WinsizeSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            Span<byte> Buffer = stackalloc byte[WinsizeSize];
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0, 2), TerminalState.Rows);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(2, 2), TerminalState.Columns);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(4, 2), TerminalState.XPixel);
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(6, 2), TerminalState.YPixel);

            if (!Instance.WriteMemory(Address, Buffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            return true;
        }

        private static bool ReadWinsizeFromGuest(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, ulong Address, LinuxTerminalState TerminalState, out bool Changed)
        {
            Changed = false;
            if (Address == 0 || !Instance.IsRegionMapped(Address, WinsizeSize))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            Span<byte> Buffer = stackalloc byte[WinsizeSize];
            if (!Instance.ReadMemory(Address, Buffer))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return false;
            }

            ushort Rows = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(0, 2));
            ushort Columns = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(2, 2));
            ushort XPixel = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(4, 2));
            ushort YPixel = BinaryPrimitives.ReadUInt16LittleEndian(Buffer.Slice(6, 2));

            Changed = Rows != TerminalState.Rows || Columns != TerminalState.Columns || XPixel != TerminalState.XPixel || YPixel != TerminalState.YPixel;
            TerminalState.Rows = Rows;
            TerminalState.Columns = Columns;
            TerminalState.XPixel = XPixel;
            TerminalState.YPixel = YPixel;
            return true;
        }

        private static void QueueSigwinch(BinaryEmulator Instance, LinuxSyscallsHelper Helper)
        {
            if (Instance.CurrentThread == null)
                return;

            LinuxSignalHelpers.QueueSignal(Instance, Helper, Instance.CurrentThread, new LinuxPendingSignal
            {
                Signal = SIGWINCH,
                Code = 0,
                FaultAddress = 0,
                MemoryAccess = default
            });
        }
    }
}
