using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;
using System.Buffers;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Open : ILinuxSyscall
    {
        private const int PATH_MAX = 4096;
        private const int O_ACCMODE = 0x3;
        private const int O_RDONLY = 0x0;
        private const int O_WRONLY = 0x1;
        private const int O_RDWR = 0x2;
        private const int O_CREAT = 0x40;
        private const int O_EXCL = 0x80;
        private const int O_TRUNC = 0x200;
        private const int O_APPEND = 0x400;
        private const int O_DIRECTORY = 0x10000;
        private const int O_NOFOLLOW = 0x20000;
        private const int O_CLOEXEC = 0x80000;
        private const int O_PATH = 0x200000;
        private const int O_TMPFILE = 0x410000;
        private const int RLIMIT_NOFILE = 7;
        private const int MAX_SYMLINK_DEPTH = 40;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
        private const uint IO_REPARSE_TAG_LX_SYMLINK = 0xA000001D;
        private const uint LX_SYMLINK_VERSION = 2;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_PARAMETER = 87;
        private const int ERROR_NOT_A_REPARSE_POINT = 4390;

        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            if (!TryReadPath(Instance, Context.Arg0, out string PathValue))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            HandleOpenPath(Instance, Helper, Context, PathValue, unchecked((int)Context.Arg1), unchecked((uint)Context.Arg2));
        }

        internal static void HandleOpenPath(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, string PathValue, int Flags, uint Mode)
        {
            HandleOpenPath(Instance, Helper, Context, PathValue, Flags, Mode, false);
        }

        internal static void HandleOpenPath(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context, string PathValue, int Flags, uint Mode, bool PathAlreadyNormalized)
        {
            string NormalizedPath = PathAlreadyNormalized ? PathValue : NormalizeLinuxPath(PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            int AccessMode = Flags & O_ACCMODE;
            if (AccessMode != O_RDONLY && AccessMode != O_WRONLY && AccessMode != O_RDWR)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if ((Flags & O_TMPFILE) == O_TMPFILE)
            {
                if (AccessMode == O_RDONLY)
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                else
                    Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EOPNOTSUPP);
                return;
            }

            if ((Flags & O_CREAT) != 0 && (Flags & O_DIRECTORY) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            bool CloseOnExec = (Flags & O_CLOEXEC) != 0;
            ulong DescriptorLimit = Helper.ResourceLimits.TryGetValue(RLIMIT_NOFILE, out LinuxResourceLimit NoFileLimit) ? NoFileLimit.Current : 1024UL;

            if (!TryResolveOpenPath(Helper, NormalizedPath, Flags, CloseOnExec, DescriptorLimit, out string FinalPath, out string HostPath, out LinuxErrno ResolveError, out long SpecialResult))
            {
                if (ResolveError == LinuxErrno.ESUCCESS)
                    Helper.SetReturnValue(Instance, Context, SpecialResult);
                else
                    Helper.SetReturnValue(Instance, Context, -(long)ResolveError);

                return;
            }

            string WriteHostPath = Helper.ResolveVirtualHostPath(FinalPath);
            if (string.IsNullOrWhiteSpace(WriteHostPath))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                return;
            }

            LinuxFileStream OverlayStream = new LinuxFileStream(FinalPath, HostPath, WriteHostPath);
            bool ExistsAsFile = OverlayStream.ExistsAsFile;
            bool ExistsAsDirectory = OverlayStream.ExistsAsDirectory;
            bool Exists = ExistsAsFile || ExistsAsDirectory;
            bool IsWriteOpen = AccessMode == O_WRONLY || AccessMode == O_RDWR || (Flags & O_TRUNC) != 0 || ((Flags & O_CREAT) != 0 && !Exists);

            if (Exists && (Flags & O_CREAT) != 0 && (Flags & O_EXCL) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EEXIST);
                return;
            }

            if (Helper.TryGetMountForPath(FinalPath, out LinuxMountEntry MountEntry) && MountEntry.ReadOnly && IsWriteOpen)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EROFS);
                return;
            }

            if (ExistsAsDirectory)
            {
                if ((Flags & O_DIRECTORY) != 0 || AccessMode == O_RDONLY || (Flags & O_PATH) != 0)
                {
                    if ((Flags & O_TRUNC) != 0 || AccessMode == O_WRONLY || AccessMode == O_RDWR)
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EISDIR);
                        return;
                    }

                    FileObject DirectoryObject = new FileObject
                    {
                        Path = FinalPath,
                        HostPath = OverlayStream.EffectiveReadHostPath,
                        FileStream = OverlayStream,
                        StatusFlags = Flags,
                        IsDirectory = true,
                        IsReadOnlyMount = Helper.TryGetMountForPath(FinalPath, out LinuxMountEntry DirectoryMountEntry) && DirectoryMountEntry.ReadOnly
                    };

                    if (!Helper.DescriptorTable.TryAddHandle(DirectoryObject, CloseOnExec, DescriptorLimit, out ulong DirectoryDescriptor))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                        return;
                    }

                    Helper.SetReturnValue(Instance, Context, DirectoryDescriptor);
                    return;
                }

                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EISDIR);
                return;
            }

            if (!Exists && (Flags & O_CREAT) == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }

            if (Exists && (Flags & O_DIRECTORY) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTDIR);
                return;
            }

            try
            {
                if ((Flags & O_CREAT) != 0 && !Exists)
                {
                    if (!TryEnsureWritableParent(Helper, FinalPath, WriteHostPath, out LinuxErrno ParentError))
                    {
                        Helper.SetReturnValue(Instance, Context, -(long)ParentError);
                        return;
                    }

                    OverlayStream.CreateEmpty();
                }

                if ((Flags & O_TRUNC) != 0 && AccessMode != O_RDONLY && (Flags & O_PATH) == 0)
                {
                    OverlayStream.Truncate();
                }
                else if ((Flags & O_PATH) == 0 && AccessMode != O_WRONLY)
                {
                    using FileStream ValidationStream = new FileStream(OverlayStream.EffectiveReadHostPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                }
            }
            catch (UnauthorizedAccessException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EACCES);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }
            catch (FileNotFoundException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOENT);
                return;
            }
            catch (PathTooLongException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENAMETOOLONG);
                return;
            }
            catch (ArgumentException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }
            catch (NotSupportedException)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }
            catch (IOException)
            {
                LinuxErrno Error = (Flags & O_CREAT) != 0 && (Flags & O_EXCL) != 0 ? LinuxErrno.EEXIST : LinuxErrno.EIO;
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            FileObject Object = new FileObject
            {
                Path = FinalPath,
                HostPath = HostPath,
                FileStream = OverlayStream,
                StatusFlags = Flags,
                Offset = 0,
                IsDirectory = false,
                IsReadOnlyMount = Helper.TryGetMountForPath(FinalPath, out LinuxMountEntry ObjectMountEntry) && ObjectMountEntry.ReadOnly
            };

            if (!Helper.DescriptorTable.TryAddHandle(Object, CloseOnExec, DescriptorLimit, out ulong Descriptor))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EMFILE);
                return;
            }

            Helper.SetReturnValue(Instance, Context, Descriptor);
        }

        private static bool TryResolveOpenPath(LinuxSyscallsHelper Helper, string PathValue, int Flags, bool CloseOnExec, ulong DescriptorLimit, out string FinalPath, out string FinalHostPath, out LinuxErrno Error, out long SpecialResult)
        {
            FinalPath = string.Empty;
            FinalHostPath = string.Empty;
            Error = LinuxErrno.ESUCCESS;
            SpecialResult = 0;

            string CurrentPath = PathValue;
            for (int Index = 0; Index < MAX_SYMLINK_DEPTH; Index++)
            {
                if (Helper.SpecialPathsHandler.TryOpenPath(Helper, CurrentPath, Flags, CloseOnExec, DescriptorLimit, out SpecialResult))
                    return false;

                string CurrentHostPath;
                if (!Helper.SpecialPathsHandler.TryResolveHostBackedPath(Helper, CurrentPath, out CurrentHostPath))
                    CurrentHostPath = Helper.ResolveHostPath(CurrentPath, PreserveFinalLink: true);
                if (string.IsNullOrEmpty(CurrentHostPath))
                {
                    Error = LinuxErrno.ENOENT;
                    return false;
                }

                if (!TryReadHostLinkTarget(CurrentHostPath, out string LinkTarget, out LinuxErrno LinkError))
                {
                    Error = LinkError;
                    return false;
                }

                if (string.IsNullOrEmpty(LinkTarget))
                {
                    FinalPath = CurrentPath;
                    FinalHostPath = CurrentHostPath;
                    return true;
                }

                if ((Flags & O_CREAT) != 0 && (Flags & O_EXCL) != 0)
                {
                    Error = LinuxErrno.EEXIST;
                    return false;
                }

                if ((Flags & O_NOFOLLOW) != 0)
                {
                    Error = LinuxErrno.ELOOP;
                    return false;
                }

                string BaseDirectory = GetLinuxDirectoryName(CurrentPath);
                string NextPath = NormalizeLinuxPath(LinkTarget, BaseDirectory);
                if (string.IsNullOrEmpty(NextPath))
                {
                    Error = LinuxErrno.ENOENT;
                    return false;
                }

                CurrentPath = NextPath;
            }

            Error = LinuxErrno.ELOOP;
            return false;
        }

        private static bool TryEnsureWritableParent(LinuxSyscallsHelper Helper, string GuestPath, string WriteHostPath, out LinuxErrno Error)
        {
            Error = LinuxErrno.ESUCCESS;

            string ParentHostPath = Path.GetDirectoryName(WriteHostPath);
            if (string.IsNullOrEmpty(ParentHostPath))
            {
                Error = LinuxErrno.ENOENT;
                return false;
            }

            string ParentGuestPath = GetLinuxDirectoryName(GuestPath);
            string ParentVirtualPath = Helper.ResolveVirtualHostPath(ParentGuestPath);
            string ParentReadPath = Helper.ResolveHostPath(ParentGuestPath);

            bool ParentExists = (!string.IsNullOrWhiteSpace(ParentVirtualPath) && Directory.Exists(ParentVirtualPath)) ||
                                (!string.IsNullOrWhiteSpace(ParentReadPath) && Directory.Exists(ParentReadPath));

            if (!ParentExists)
            {
                Error = LinuxErrno.ENOENT;
                return false;
            }

            try
            {
                Directory.CreateDirectory(ParentHostPath);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Error = LinuxErrno.EACCES;
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                Error = LinuxErrno.ENOENT;
                return false;
            }
            catch (PathTooLongException)
            {
                Error = LinuxErrno.ENAMETOOLONG;
                return false;
            }
            catch (ArgumentException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (NotSupportedException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (IOException)
            {
                Error = LinuxErrno.EIO;
                return false;
            }
        }

        private static bool TryReadHostLinkTarget(string HostPath, out string LinkTarget, out LinuxErrno Error)
        {
            LinkTarget = null;
            Error = LinuxErrno.ESUCCESS;

            if (OperatingSystem.IsWindows())
                return TryReadWindowsHostLinkTarget(HostPath, out LinkTarget, out Error);

            try
            {
                FileAttributes Attributes = File.GetAttributes(HostPath);
                FileSystemInfo Entry = (Attributes & FileAttributes.Directory) != 0 ? new DirectoryInfo(HostPath) : new FileInfo(HostPath);
                LinkTarget = Entry.LinkTarget;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Error = LinuxErrno.EACCES;
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                LinkTarget = null;
                return true;
            }
            catch (FileNotFoundException)
            {
                LinkTarget = null;
                return true;
            }
            catch (PathTooLongException)
            {
                Error = LinuxErrno.ENAMETOOLONG;
                return false;
            }
            catch (ArgumentException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (NotSupportedException)
            {
                Error = LinuxErrno.EINVAL;
                return false;
            }
            catch (IOException)
            {
                Error = LinuxErrno.EIO;
                return false;
            }
        }

        private static bool TryReadWindowsHostLinkTarget(string HostPath, out string LinkTarget, out LinuxErrno Error)
        {
            LinkTarget = null;
            Error = LinuxErrno.ESUCCESS;

            using SafeFileHandle Handle = NativeWinImports.CreateFileW(HostPath, 0, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero, FileMode.Open, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (Handle.IsInvalid)
            {
                int LastError = Marshal.GetLastWin32Error();
                if (LastError == ERROR_FILE_NOT_FOUND || LastError == ERROR_PATH_NOT_FOUND)
                    return true;

                Error = MapHostOpenError(LastError);
                return false;
            }

            byte[] Buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
            try
            {
                if (!NativeWinImports.DeviceIoControl(Handle, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, Buffer, Buffer.Length, out int BytesReturned, IntPtr.Zero))
                {
                    int LastError = Marshal.GetLastWin32Error();
                    if (LastError == ERROR_NOT_A_REPARSE_POINT)
                        return true;

                    Error = MapHostOpenError(LastError);
                    return false;
                }

                return TryParseWindowsReparseTarget(Buffer, BytesReturned, out LinkTarget, out Error);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        private static bool TryParseWindowsReparseTarget(byte[] Buffer, int BytesReturned, out string LinkTarget, out LinuxErrno Error)
        {
            LinkTarget = null;
            Error = LinuxErrno.ESUCCESS;

            if (BytesReturned < 12)
            {
                Error = LinuxErrno.EIO;
                return false;
            }

            uint Tag = BitConverter.ToUInt32(Buffer, 0);
            if (Tag != IO_REPARSE_TAG_LX_SYMLINK)
            {
                Error = LinuxErrno.EACCES;
                return false;
            }

            uint Version = BitConverter.ToUInt32(Buffer, 8);
            if (Version != LX_SYMLINK_VERSION)
            {
                Error = LinuxErrno.EIO;
                return false;
            }

            int DataLength = BitConverter.ToUInt16(Buffer, 4);
            int TargetLength = DataLength - 4;
            if (TargetLength < 0 || 12 + TargetLength > BytesReturned)
            {
                Error = LinuxErrno.EIO;
                return false;
            }

            int End = 12 + TargetLength;
            while (End > 12 && Buffer[End - 1] == 0)
                End--;

            LinkTarget = Encoding.UTF8.GetString(Buffer, 12, End - 12);
            return true;
        }

        private static LinuxErrno MapHostOpenError(int ErrorCode)
        {
            return ErrorCode switch
            {
                ERROR_ACCESS_DENIED => LinuxErrno.EACCES,
                ERROR_INVALID_PARAMETER => LinuxErrno.EINVAL,
                _ => LinuxErrno.EIO
            };
        }

        internal static string GetLinuxDirectoryName(string PathValue)
        {
            if (string.IsNullOrEmpty(PathValue) || PathValue == "/")
                return "/";

            int LastSlash = PathValue.LastIndexOf('/');
            if (LastSlash <= 0)
                return "/";

            return PathValue.Substring(0, LastSlash);
        }

        internal static bool TryReadPath(BinaryEmulator Instance, ulong Address, out string Value)
        {
            Value = string.Empty;

            if (Address == 0)
                return false;

            Span<byte> Bytes = stackalloc byte[PATH_MAX];
            Span<byte> CurrentByte = stackalloc byte[1];
            int Count = 0;
            
            // the reason we read byte-by-byte is because unicorn will fail if we read from a region beyond what is allocated, so we can't read in a bulk.
            // it took at maximum 100 microseconds when testing with random samples.
            for (int i = 0; i < PATH_MAX; i++)
            {
                ulong Current = Address + (ulong)i;
                if (!Instance.IsRegionMapped(Current, 1) || !Instance.ReadMemory(Current, CurrentByte))
                    break;

                byte b = CurrentByte[0];
                if (b == 0)
                {
                    Value = Encoding.ASCII.GetString(Bytes.Slice(0, Count));
                    return true;
                }

                Bytes[Count++] = b;
            }

            Value = Encoding.ASCII.GetString(Bytes.Slice(0, Count));
            return Count > 0;
        }

        internal static string NormalizeLinuxPath(string PathValue, string BaseDirectory = null)
        {
            if (string.IsNullOrWhiteSpace(PathValue))
                return null;

            string LinuxPath = PathValue.Replace('\\', '/').Trim().TrimEnd('\0', ' ');
            if (LinuxPath.Length == 0)
                return null;

            if (!LinuxPath.StartsWith("/", StringComparison.Ordinal))
            {
                string CurrentDirectory = string.IsNullOrWhiteSpace(BaseDirectory) ? GeneralHelper.IO.LinuxCurrentDirectory : BaseDirectory;
                if (string.IsNullOrWhiteSpace(CurrentDirectory))
                    CurrentDirectory = "/";

                if (!CurrentDirectory.StartsWith("/", StringComparison.Ordinal))
                    CurrentDirectory = "/" + CurrentDirectory;

                LinuxPath = CurrentDirectory.TrimEnd('/') + "/" + LinuxPath;
            }

            List<string> Parts = new List<string>();
            foreach (string Part in LinuxPath.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                if (Part == ".")
                    continue;

                if (Part == "..")
                {
                    if (Parts.Count > 0)
                        Parts.RemoveAt(Parts.Count - 1);

                    continue;
                }

                Parts.Add(Part);
            }

            if (Parts.Count == 0)
                return "/";

            return "/" + string.Join('/', Parts);
        }

    }
}