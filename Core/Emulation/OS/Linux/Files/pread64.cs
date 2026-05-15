using System;
using System.IO;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Pread64 : ILinuxSyscall
    {
        private const int O_ACCMODE = 0x3;
        private const int O_WRONLY = 0x1;
        private const int O_PATH = 0x200000;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong buf = Context.Arg1;
            ulong count = Context.Arg2;
            ulong offsetValue = GetOffset(Context);
            long offset = unchecked((long)offsetValue);

            if (offset < 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

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
                    BytesRead = FileDesc.FileStream.ReadAt(offset, Transfer);
                }
                else
                {
                    using FileStream Stream = new FileStream(FileDesc.HostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    Stream.Seek(offset, SeekOrigin.Begin);
                    BytesRead = Stream.Read(Transfer);
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

        private static ulong GetOffset(LinuxSyscallContext Context)
        {
            if (Context.Abi == SyscallAbi.X86)
                return Context.Arg3 | (Context.Arg4 << 32);

            return Context.Arg3;
        }
    }
}
