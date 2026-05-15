using System;
using System.Buffers.Binary;
using System.Threading;
using System.IO;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Read : ILinuxSyscall
    {
        private const int O_ACCMODE = 0x3;
        private const int O_WRONLY = 0x1;
        private const int O_PATH = 0x200000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong buf = Context.Arg1;
            ulong count = Context.Arg2;

            if (count == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (count > int.MaxValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (Entry.Object is SocketObject SocketDesc)
            {
                ReadSocket(Instance, Helper, Context, SocketDesc, buf, count);
                return;
            }

            if (Entry.Object is EventfdObject EventfdDesc)
            {
                LinuxEventHelpers.ReadEventfd(Instance, Helper, Context, EventfdDesc, buf, count);
                return;
            }

            if (Entry.Object is TimerfdObject TimerfdDesc)
            {
                LinuxEventHelpers.ReadTimerfd(Instance, Helper, Context, TimerfdDesc, buf, count);
                return;
            }

            if (Entry.Object is EpollObject)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (Entry.Object is not FileObject FileDesc)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if ((FileDesc.StatusFlags & O_ACCMODE) == O_WRONLY || (FileDesc.StatusFlags & O_PATH) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (FileDesc.IsDirectory)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EISDIR);
                return;
            }

            if (FileDesc.IsSpecialPath)
            {
                if (Helper.SpecialPathsHandler.TryHandle(Instance, Helper, FileDesc, buf, count, false, out long Result))
                {
                    Helper.SetReturnValue(Instance, Context, Result);
                    return;
                }

                Instance.TriggerEventMessage($"[!] Special path handler not set for {FileDesc.Path}.", LogFlags.Important);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENODEV);
                return;
            }

            if (!Instance.IsRegionMapped(buf, count))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            try
            {
                Span<byte> Transfer = Helper.Shared.GetSpan(count);
                int BytesRead;

                if (FileDesc.FileStream != null)
                {
                    FileDesc.FileStream.Position = (long)FileDesc.Offset;
                    BytesRead = FileDesc.FileStream.Read(Transfer);
                    FileDesc.Offset = (ulong)FileDesc.FileStream.Position;
                }
                else
                {
                    using FileStream Stream = new FileStream(FileDesc.HostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    Stream.Seek((long)FileDesc.Offset, SeekOrigin.Begin);
                    BytesRead = Stream.Read(Transfer);
                    FileDesc.Offset += (ulong)BytesRead;
                }

                if (BytesRead > 0 && !Instance.WriteMemory(buf, Transfer.Slice(0, BytesRead)))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, (long)BytesRead);
            }
            catch (UnauthorizedAccessException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
            }
            catch (DirectoryNotFoundException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
            }
            catch (FileNotFoundException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
            }
            catch (IOException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EIO);
            }
        }

        private static void ReadSocket(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, SocketObject SocketDesc, ulong BufferAddress, ulong Count)
        {
            if (!Instance.IsRegionMapped(BufferAddress, Count))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (SocketDesc.NonBlocking && SocketHelpers.WouldBlock(SocketDesc, SelectMode.SelectRead))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EAGAIN);
                return;
            }

            if (!SocketHelpers.TryCheckSocketRemotePolicy(Instance, SocketDesc, true, out LinuxErrno Error))
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            try
            {
                Span<byte> Transfer = Helper.Shared.GetSpan(Count);
                int Received = SocketDesc.Handle.Receive(Transfer, SocketFlags.None);

                if (Received > 0 && !Instance.WriteMemory(BufferAddress, Transfer.Slice(0, Received)))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, Received);
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