using System;
using System.Buffers.Binary;
using System.Threading;
using System.IO;
using System.Net.Sockets;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Write : ILinuxSyscall
    {
        private const int O_ACCMODE = 0x3;
        private const int O_RDONLY = 0x0;
        private const int O_APPEND = 0x400;
        private const int O_PATH = 0x200000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong data = Context.Arg1;
            ulong length = Context.Arg2;

            if (length == 0)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (length > int.MaxValue)
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
                WriteSocket(Instance, Helper, Context, SocketDesc, data, length);
                return;
            }

            if (Entry.Object is EventfdObject EventfdDesc)
            {
                LinuxEventHelpers.WriteEventfd(Instance, Helper, Context, EventfdDesc, data, length);
                return;
            }

            if (Entry.Object is TimerfdObject || Entry.Object is EpollObject)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (Entry.Object is not FileObject FObj)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if ((FObj.StatusFlags & O_ACCMODE) == O_RDONLY || (FObj.StatusFlags & O_PATH) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (FObj.IsReadOnlyMount)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EROFS);
                return;
            }

            if (FObj.IsDirectory)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EISDIR);
                return;
            }

            if (FObj.IsSpecialPath)
            {
                if (Helper.SpecialPathsHandler.TryHandle(Instance, Helper, FObj, data, length, true, out long Result))
                {
                    Helper.SetReturnValue(Instance, Context, Result);
                    return;
                }

                Instance.TriggerEventMessage($"[!] Special path handler not set for {FObj.Path}.", LogFlags.Important);
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENODEV);
                return;
            }

            if (!Instance.IsRegionMapped(data, length))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            try
            {
                Span<byte> Transfer = Helper.Shared.GetSpan(length);
                if (!Instance.ReadMemory(data, Transfer))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                if (FObj.FileStream != null)
                {
                    if ((FObj.StatusFlags & O_APPEND) != 0)
                    {
                        FObj.FileStream.WriteAppend(Transfer);
                    }
                    else
                    {
                        FObj.FileStream.Position = (long)FObj.Offset;
                        FObj.FileStream.Write(Transfer);
                    }

                    FObj.Offset = (ulong)FObj.FileStream.Position;
                }
                else
                {
                    using FileStream Output = new FileStream(FObj.HostPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

                    if ((FObj.StatusFlags & O_APPEND) != 0)
                    {
                        Output.Seek(0, SeekOrigin.End);
                    }
                    else
                    {
                        Output.Seek((long)FObj.Offset, SeekOrigin.Begin);
                    }

                    Output.Write(Transfer);
                    Output.Flush();
                    FObj.Offset = (ulong)Output.Position;
                }

                Helper.SetReturnValue(Instance, Context, unchecked((long)length));
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

        private static void WriteSocket(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, SocketObject SocketDesc, ulong Data, ulong Length)
        {
            if (!Instance.IsRegionMapped(Data, Length))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (SocketDesc.NonBlocking && SocketHelpers.WouldBlock(SocketDesc, SelectMode.SelectWrite))
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
                Span<byte> Transfer = Helper.Shared.GetSpan(Length);
                if (!Instance.ReadMemory(Data, Transfer))
                {
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                    return;
                }

                int Sent = SocketDesc.Handle.Send(Transfer, SocketFlags.None);
                Helper.SetReturnValue(Instance, Context, Sent);
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