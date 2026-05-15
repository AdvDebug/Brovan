using System;
using System.IO;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Access : ILinuxSyscall
    {
        private const int F_OK = 0;
        private const int X_OK = 1;
        private const int W_OK = 2;
        private const int R_OK = 4;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            if (!Open.TryReadPath(Instance, Context.Arg0, out string PathValue))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            if (string.IsNullOrEmpty(PathValue))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            int Mode = unchecked((int)Context.Arg1);
            if ((Mode & ~(R_OK | W_OK | X_OK)) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            string NormalizedPath = Helper.NormalizePath(PathValue) ?? PathValue;
            if (Helper.SpecialPathsHandler.TryAccess(Helper, NormalizedPath, Mode, out long SpecialResult))
            {
                Helper.SetReturnValue(Instance, Context, SpecialResult);
                return;
            }

            string HostPath;
            if (!Helper.SpecialPathsHandler.TryResolveHostBackedPath(Helper, NormalizedPath, out HostPath))
                HostPath = Helper.ResolveHostPath(NormalizedPath);
            if (string.IsNullOrEmpty(HostPath))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            string WriteHostPath = Helper.ResolveVirtualHostPath(NormalizedPath);
            if (string.IsNullOrWhiteSpace(WriteHostPath))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                return;
            }

            LinuxFileStream OverlayStream = new LinuxFileStream(NormalizedPath, HostPath, WriteHostPath);
            bool ExistsAsFile = OverlayStream.ExistsAsFile;
            bool ExistsAsDirectory = OverlayStream.ExistsAsDirectory;
            if (!ExistsAsFile && !ExistsAsDirectory)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            if (Helper.TryGetMountForPath(NormalizedPath, out LinuxMountEntry MountEntry) && MountEntry.ReadOnly && (Mode & W_OK) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EROFS);
                return;
            }

            if (Mode == F_OK)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            if (ExistsAsDirectory)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            try
            {
                if ((Mode & R_OK) != 0)
                {
                    using FileStream ReadStream = new FileStream(OverlayStream.EffectiveReadHostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                }

                if ((Mode & W_OK) != 0)
                {
                    string Parent = Path.GetDirectoryName(WriteHostPath);
                    if (string.IsNullOrEmpty(Parent))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                        return;
                    }

                    if (!Directory.Exists(Parent))
                    {
                        string ParentGuest = Open.GetLinuxDirectoryName(NormalizedPath);
                        string ParentReadPath = Helper.ResolveHostPath(ParentGuest);
                        if (string.IsNullOrWhiteSpace(ParentReadPath) || !Directory.Exists(ParentReadPath))
                        {
                            Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                            return;
                        }
                    }
                }

                if ((Mode & X_OK) != 0)
                {
                    Helper.SetReturnValue(Instance, Context, 0L);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, 0L);
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
            catch (PathTooLongException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENAMETOOLONG);
            }
            catch (ArgumentException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
            }
            catch (NotSupportedException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
            }
            catch (IOException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EIO);
            }
        }

    }
}
