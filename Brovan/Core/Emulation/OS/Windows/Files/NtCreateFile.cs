using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateFile : IWinSyscall
    {
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
        internal const uint FILE_DELETE_ON_CLOSE = 0x00001000;

        private const uint FILE_SUPERSEDE = 0;
        private const uint FILE_OPEN = 1;
        private const uint FILE_CREATE = 2;
        private const uint FILE_OPEN_IF = 3;
        private const uint FILE_OVERWRITE = 4;
        private const uint FILE_OVERWRITE_IF = 5;

        private const uint FILE_SUPERSEDED_INFORMATION = 0;
        private const uint FILE_OPENED_INFORMATION = 1;
        private const uint FILE_CREATED_INFORMATION = 2;
        private const uint FILE_OVERWRITTEN_INFORMATION = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong FileHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(3);
            uint ShareAccess = (uint)Instance.WinHelper.GetArg64(6);
            uint CreateDisposition = (uint)Instance.WinHelper.GetArg64(7);
            uint CreateOptions = (uint)Instance.WinHelper.GetArg64(8);
            ulong EaBufferPtr = Instance.WinHelper.GetArg64(9);
            uint EaLength = (uint)Instance.WinHelper.GetArg64(10, true);

            if (FileHandlePtr == 0 || ObjectAttributesPtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileHandlePtr, sizeof(ulong)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out ulong AttributesRoot, out string ObjectName, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            string RawPath = FullName;
            ulong RootDirectoryHandle = AttributesRoot;


            bool Inherit = (Instance.WinHelper.ReadObjectAttributesFlags(ObjectAttributesPtr) & WinSysHelper.OBJ_INHERIT) != 0;

            if (IsConsoleRelativeObject(ObjectName, RootDirectoryHandle, Instance) || IsConsolePath(RawPath))
            {
                ulong HandleValue = OpenConsoleObject(Instance, RawPath, (AccessMask)DesiredAccess, Inherit);
                Instance._emulator.WriteMemory(FileHandlePtr, HandleValue);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (TryOpenPipeRelative(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, RootDirectoryHandle, ObjectName, CreateOptions, Inherit, out NTSTATUS PipeStatus))
                return PipeStatus;

            string Normalized = NormalizeNtObjectPath(RawPath);

            byte[] Ea = Array.Empty<byte>();
            if (EaBufferPtr != 0 && EaLength != 0 && Instance.IsRegionMapped(EaBufferPtr, EaLength))
                Ea = Instance.ReadMemory(EaBufferPtr, EaLength);

            if (TryGetDosVolumeDevicePath(Instance, Normalized, out string VolumeDevicePath))
            {
                if (Instance.WinHelper.TryCreateDevice(VolumeDevicePath, Ea, out string VolumeInternalPath, out WinDeviceDelegate VolumeHandler, out NTSTATUS VolumeStatus))
                {
                    if (VolumeStatus != NTSTATUS.STATUS_SUCCESS)
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, VolumeStatus, 0);
                        return VolumeStatus;
                    }

                    return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, VolumeInternalPath, VolumeHandler);
                }

                return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, VolumeDevicePath, null);
            }

            if (!IsRootRelativeName(RawPath, RootDirectoryHandle) &&
                TryOpenPipeDirectory(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, Normalized, CreateDisposition, CreateOptions, Inherit, out NTSTATUS DirectoryStatus))
                return DirectoryStatus;

            if (!IsRootRelativeName(RawPath, RootDirectoryHandle) &&
                Instance.WinHelper.TryCreateDevice(Normalized, Ea, out string DevicePath, out WinDeviceDelegate DeviceHandler, out GuestNamedPipe DevicePipe, out NTSTATUS DeviceStatus))
            {
                if (DeviceStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, DeviceStatus, 0);
                    return DeviceStatus;
                }

                return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, DevicePath, DeviceHandler, DevicePipe, CreateOptions, Inherit);
            }

            string Path = ResolveNtPath(Instance, RawPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            return CreateRegularHandle64(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, Path, CreateDisposition, CreateOptions, ShareAccess, Inherit);
        }

        private NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint FileHandlePtr = Instance.WinHelper.GetArg32(0);
            uint DesiredAccess = Instance.WinHelper.GetArg32(1);
            uint ObjectAttributesPtr = Instance.WinHelper.GetArg32(2);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(3);
            uint ShareAccess = Instance.WinHelper.GetArg32(6);
            uint CreateDisposition = Instance.WinHelper.GetArg32(7);
            uint CreateOptions = Instance.WinHelper.GetArg32(8);
            uint EaBufferPtr = Instance.WinHelper.GetArg32(9);
            uint EaLength = Instance.WinHelper.GetArg32(10);

            if (FileHandlePtr == 0 || ObjectAttributesPtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileHandlePtr, sizeof(uint)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName32(ObjectAttributesPtr, out uint RootDirectoryHandle, out _, out string ObjectName, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            string RawPath = FullName;


            bool Inherit = (Instance.WinHelper.ReadObjectAttributesFlags(ObjectAttributesPtr) & WinSysHelper.OBJ_INHERIT) != 0;

            if (IsConsoleRelativeObject(ObjectName, RootDirectoryHandle, Instance) || IsConsolePath(RawPath))
            {
                uint HandleValue = (uint)OpenConsoleObject(Instance, RawPath, (AccessMask)DesiredAccess, Inherit);
                Instance._emulator.WriteMemory(FileHandlePtr, HandleValue);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (TryOpenPipeRelative(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, RootDirectoryHandle, ObjectName, CreateOptions, Inherit, out NTSTATUS PipeStatus))
                return PipeStatus;

            string Normalized = NormalizeNtObjectPath(RawPath);

            byte[] Ea = Array.Empty<byte>();
            if (EaBufferPtr != 0 && EaLength != 0 && Instance.IsRegionMapped(EaBufferPtr, EaLength))
                Ea = Instance.ReadMemory(EaBufferPtr, EaLength);

            if (TryGetDosVolumeDevicePath(Instance, Normalized, out string VolumeDevicePath))
            {
                if (Instance.WinHelper.TryCreateDevice(VolumeDevicePath, Ea, out string VolumeInternalPath, out WinDeviceDelegate VolumeHandler, out NTSTATUS VolumeStatus))
                {
                    if (VolumeStatus != NTSTATUS.STATUS_SUCCESS)
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, VolumeStatus, 0);
                        return VolumeStatus;
                    }

                    return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, VolumeInternalPath, VolumeHandler);
                }

                return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, VolumeDevicePath, null);
            }

            if (!IsRootRelativeName(RawPath, RootDirectoryHandle) &&
                TryOpenPipeDirectory(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, Normalized, CreateDisposition, CreateOptions, Inherit, out NTSTATUS DirectoryStatus))
                return DirectoryStatus;

            if (!IsRootRelativeName(RawPath, RootDirectoryHandle) &&
                Instance.WinHelper.TryCreateDevice(Normalized, Ea, out string DevicePath, out WinDeviceDelegate DeviceHandler, out GuestNamedPipe DevicePipe, out NTSTATUS DeviceStatus))
            {
                if (DeviceStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, DeviceStatus, 0);
                    return DeviceStatus;
                }

                return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, DevicePath, DeviceHandler, DevicePipe, CreateOptions, Inherit);
            }

            string Path = ResolveNtPath(Instance, RawPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            return CreateRegularHandle32(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, Path, CreateDisposition, CreateOptions, ShareAccess, Inherit);
        }

        private static NTSTATUS CreateRegularHandle64(BinaryEmulator Instance, ulong FileHandlePtr, ulong IoStatusBlockPtr, AccessMask Permissions, string Path, uint CreateDisposition, uint CreateOptions, uint ShareAccess, bool Inherit)
        {
            Path = NormalizeAndTrimPath(Path);
            bool IsDirectory = (CreateOptions & FILE_DIRECTORY_FILE) != 0 || Path.EndsWith("\\", StringComparison.Ordinal);

            if ((CreateOptions & FILE_DIRECTORY_FILE) != 0 && (CreateOptions & FILE_NON_DIRECTORY_FILE) != 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if ((CreateOptions & FILE_NON_DIRECTORY_FILE) != 0 && IsDirectory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_INVALID, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;
            }

            bool DeleteOnClose = (CreateOptions & FILE_DELETE_ON_CLOSE) != 0;
            if (DeleteOnClose && !HasDeleteAccess(Permissions))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            NTSTATUS Status = LookUpRegularPath(Instance, Path, Permissions, CreateDisposition, CreateOptions, ShareAccess, ref IsDirectory, out WindowsFileStream Stream, out bool Exists, out bool ParentExists);
            uint Information = FILE_OPENED_INFORMATION;
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = PreparePathForDisposition(Stream, IsDirectory, Exists, ParentExists, CreateDisposition, out Information);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Stream.Dispose();
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return Status;
            }

            bool FinalExists = Information != FILE_OPENED_INFORMATION || (IsDirectory ? Stream.ExistsAsDirectory : Stream.ExistsAsFile);

            WinFile FileObj = new WinFile
            {
                Path = Path,
                Device = false,
                Real = FinalExists,
                Directory = IsDirectory,
                Position = 0,
                Handler = null,
                FileStream = Stream,
                DeletePending = DeleteOnClose,
                GrantedAccess = Permissions,
                ShareAccess = ShareAccess,
                Mode = ModeFromCreateOptions(CreateOptions)
            };

            Instance.WinHelper.WinFiles.Add(FileObj);
            Instance.WinHelper.RegisterOpenFile(FileObj);

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);
            if (Inherit)
                Instance.WinHelper.HandleManager.SetHandleFlags(Handle.Handle, ObjectHandleFlags.Inherit);

            Instance._emulator.WriteMemory(FileHandlePtr, (ulong)Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Information);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CreateRegularHandle32(BinaryEmulator Instance, uint FileHandlePtr, uint IoStatusBlockPtr, AccessMask Permissions, string Path, uint CreateDisposition, uint CreateOptions, uint ShareAccess, bool Inherit)
        {
            Path = NormalizeAndTrimPath(Path);
            bool IsDirectory = (CreateOptions & FILE_DIRECTORY_FILE) != 0 || Path.EndsWith("\\", StringComparison.Ordinal);

            if ((CreateOptions & FILE_DIRECTORY_FILE) != 0 && (CreateOptions & FILE_NON_DIRECTORY_FILE) != 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if ((CreateOptions & FILE_NON_DIRECTORY_FILE) != 0 && IsDirectory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_INVALID, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;
            }

            bool DeleteOnClose = (CreateOptions & FILE_DELETE_ON_CLOSE) != 0;
            if (DeleteOnClose && !HasDeleteAccess(Permissions))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            NTSTATUS Status = LookUpRegularPath(Instance, Path, Permissions, CreateDisposition, CreateOptions, ShareAccess, ref IsDirectory, out WindowsFileStream Stream, out bool Exists, out bool ParentExists);
            uint Information = FILE_OPENED_INFORMATION;
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = PreparePathForDisposition(Stream, IsDirectory, Exists, ParentExists, CreateDisposition, out Information);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Stream.Dispose();
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return Status;
            }

            bool FinalExists = Information != FILE_OPENED_INFORMATION || (IsDirectory ? Stream.ExistsAsDirectory : Stream.ExistsAsFile);

            WinFile FileObj = new WinFile
            {
                Path = Path,
                Device = false,
                Real = FinalExists,
                Directory = IsDirectory,
                Position = 0,
                Handler = null,
                FileStream = Stream,
                DeletePending = DeleteOnClose,
                GrantedAccess = Permissions,
                ShareAccess = ShareAccess,
                Mode = ModeFromCreateOptions(CreateOptions)
            };

            Instance.WinHelper.WinFiles.Add(FileObj);
            Instance.WinHelper.RegisterOpenFile(FileObj);

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);
            if (Inherit)
                Instance.WinHelper.HandleManager.SetHandleFlags(Handle.Handle, ObjectHandleFlags.Inherit);

            Instance._emulator.WriteMemory(FileHandlePtr, (uint)Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Information);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // Runs in one probe scope, so nothing here may create or change a host entry.
        private static NTSTATUS LookUpRegularPath(BinaryEmulator Instance, string Path, AccessMask Permissions, uint CreateDisposition, uint CreateOptions, uint ShareAccess, ref bool IsDirectory, out WindowsFileStream Stream, out bool Exists, out bool ParentExists)
        {
            using GeneralHelper.IO.ProbeScope Scope = GeneralHelper.IO.BeginProbeScope();

            Stream = WindowsFileStream.FromGuestPath(Path);
            Stream.OpenForLookup(WantsReadData(Permissions));
            bool DirectoryExists = Stream.ExistsAsDirectory || IsDriveRootPath(Path);
            bool FileExists = Stream.ExistsAsFile;

            // With neither FILE_DIRECTORY_FILE nor FILE_NON_DIRECTORY_FILE the caller takes whatever is
            // there. CreateFile(FILE_FLAG_BACKUP_SEMANTICS) directory handle exactly that way
            IsDirectory = IsDirectory || (DirectoryExists && (CreateOptions & FILE_NON_DIRECTORY_FILE) == 0);
            Exists = IsDirectory ? DirectoryExists : FileExists;
            ParentExists = true;

            if (IsDirectory && FileExists)
                return NTSTATUS.STATUS_NOT_A_DIRECTORY;

            if (!IsDirectory && DirectoryExists)
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;

            if ((CreateOptions & FILE_DELETE_ON_CLOSE) != 0 && Stream.IsReadOnly)
                return NTSTATUS.STATUS_CANNOT_DELETE;

            if (!IsDirectory && RefusesWriteAccess(Stream, Permissions, CreateDisposition))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (!Instance.WinHelper.ShareAccessAllows(Path, Permissions, ShareAccess))
                return NTSTATUS.STATUS_SHARING_VIOLATION;

            ParentExists = Exists || (Stream.KnownParentExists ?? ParentDirectoryExists(Path));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS PreparePathForDisposition(WindowsFileStream Stream, bool IsDirectory, bool Exists, bool ParentExists, uint CreateDisposition, out uint Information)
        {
            Information = FILE_OPENED_INFORMATION;

            if (!ParentExists)
                return NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;

            if (IsDirectory)
            {
                switch (CreateDisposition)
                {
                    case FILE_OPEN:
                        if (!Exists)
                            return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                        Information = FILE_OPENED_INFORMATION;
                        return NTSTATUS.STATUS_SUCCESS;

                    case FILE_CREATE:
                        if (Exists)
                            return NTSTATUS.STATUS_OBJECT_NAME_COLLISION;

                        if (!CreateDirectory(Stream))
                            return NTSTATUS.STATUS_ACCESS_DENIED;

                        Information = FILE_CREATED_INFORMATION;
                        return NTSTATUS.STATUS_SUCCESS;

                    case FILE_OPEN_IF:
                        if (!Exists)
                        {
                            if (!CreateDirectory(Stream))
                                return NTSTATUS.STATUS_ACCESS_DENIED;

                            Information = FILE_CREATED_INFORMATION;
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                        Information = FILE_OPENED_INFORMATION;
                        return NTSTATUS.STATUS_SUCCESS;

                    case FILE_SUPERSEDE:
                    case FILE_OVERWRITE:
                    case FILE_OVERWRITE_IF:
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    default:
                        return NTSTATUS.STATUS_INVALID_PARAMETER;
                }
            }

            switch (CreateDisposition)
            {
                case FILE_SUPERSEDE:
                    if (!CreateOrTruncateFile(Stream))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = FILE_SUPERSEDED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OPEN:
                    if (!Exists)
                        return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                    Information = FILE_OPENED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_CREATE:
                    if (Exists)
                        return NTSTATUS.STATUS_OBJECT_NAME_COLLISION;

                    if (!CreateOrTruncateFile(Stream))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = FILE_CREATED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OPEN_IF:
                    if (!Exists)
                    {
                        if (!CreateOrTruncateFile(Stream))
                            return NTSTATUS.STATUS_ACCESS_DENIED;

                        Information = FILE_CREATED_INFORMATION;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                    Information = FILE_OPENED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OVERWRITE:
                    if (!Exists)
                        return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                    if (!CreateOrTruncateFile(Stream))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = FILE_OVERWRITTEN_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OVERWRITE_IF:
                    if (!CreateOrTruncateFile(Stream))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = Exists ? FILE_OVERWRITTEN_INFORMATION : FILE_CREATED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
        }

        // FILE_WRITE_ATTRIBUTES and DELETE stay allowed on a read-only file.
        internal static bool RefusesWriteAccess(WindowsFileStream Stream, AccessMask Permissions, uint CreateDisposition)
        {
            bool WantsWrite = (Permissions & AccessMask.FileWriteData) == AccessMask.FileWriteData
                || (Permissions & AccessMask.FileAppendData) == AccessMask.FileAppendData
                || (Permissions & AccessMask.GenericWrite) == AccessMask.GenericWrite
                || (Permissions & AccessMask.GenericAll) == AccessMask.GenericAll
                || (Permissions & AccessMask.FileAllAccess) == AccessMask.FileAllAccess;

            if (!WantsWrite && CreateDisposition != FILE_OVERWRITE && CreateDisposition != FILE_OVERWRITE_IF
                && CreateDisposition != FILE_SUPERSEDE)
                return false;

            return Stream != null && Stream.IsReadOnly;
        }

        internal static bool WantsReadData(AccessMask Permissions)
        {
            return (Permissions & AccessMask.FileReadData) == AccessMask.FileReadData
                || (Permissions & AccessMask.GenericRead) == AccessMask.GenericRead
                || (Permissions & AccessMask.GenericAll) == AccessMask.GenericAll
                || (Permissions & AccessMask.FileAllAccess) == AccessMask.FileAllAccess
                || (Permissions & AccessMask.MaximumAllowed) != 0;
        }

        /// <summary>
        /// Reports whether the granted access allows FILE_DELETE_ON_CLOSE, which NT accepts only with DELETE.
        /// </summary>
        internal static bool HasDeleteAccess(AccessMask Permissions)
        {
            if ((Permissions & AccessMask.MaximumAllowed) != 0)
                return true;

            if ((Permissions & AccessMask.GenericAll) == AccessMask.GenericAll)
                return true;

            if ((Permissions & AccessMask.FileAllAccess) == AccessMask.FileAllAccess)
                return true;

            return (Permissions & AccessMask.Delete) == AccessMask.Delete;
        }

        private static bool CreateOrTruncateFile(WindowsFileStream Stream)
        {
            try
            {
                Stream.Truncate();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool CreateDirectory(WindowsFileStream Stream)
        {
            try
            {
                Stream.CreateDirectory();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeRegularPath(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return string.Empty;

            return Path.Replace('/', '\\').TrimEnd('\0');
        }

        private static string TrimTrailingDirectorySeparators(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return Path;
            while (Path.Length > 3 && Path.EndsWith("\\", StringComparison.Ordinal))
                Path = Path.Substring(0, Path.Length - 1);
            return Path;
        }

        private static string NormalizeAndTrimPath(string Path)
        {
            if (string.IsNullOrEmpty(Path)) return string.Empty;
            int End = Path.Length;
            while (End > 0 && Path[End - 1] == '\0') End--;
            while (End > 3 && Path[End - 1] == '\\') End--;
            bool HasSlash = false;
            for (int I = 0; I < End; I++) { if (Path[I] == '/') { HasSlash = true; break; } }
            if (!HasSlash && End == Path.Length) return Path;
            char[] Buf = new char[End];
            for (int I = 0; I < End; I++) { char C = Path[I]; Buf[I] = C == '/' ? '\\' : C; }
            return new string(Buf);
        }

        /// <summary>
        /// NT resolves a relative name against the RootDirectory handle, so it never reaches a device.
        /// </summary>
        internal static bool IsRootRelativeName(string RawPath, ulong RootDirectoryHandle)
        {
            return RootDirectoryHandle != 0 && !string.IsNullOrEmpty(RawPath) &&
                   !RawPath.StartsWith("\\", StringComparison.Ordinal);
        }

        internal static NTSTATUS CreateDeviceHandle(BinaryEmulator Instance, ulong FileHandlePtr, ulong IoStatusBlockPtr, AccessMask Permissions, string InternalPath, WinDeviceDelegate Handler, GuestNamedPipe Pipe = null, uint CreateOptions = 0, bool Inherit = false)
        {
            WinFile FileObj = new WinFile
            {
                Path = InternalPath,
                Device = true,
                Real = false,
                Directory = false,
                Position = 0,
                Mode = ModeFromCreateOptions(CreateOptions),
                Handler = Handler,
                Pipe = Pipe
            };

            Instance.WinHelper.WinFiles.Add(FileObj);
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);
            if (Inherit)
                Instance.WinHelper.HandleManager.SetHandleFlags(Handle.Handle, ObjectHandleFlags.Inherit);

            Instance.WinHelper.WritePointer(FileHandlePtr, Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static uint ModeFromCreateOptions(uint CreateOptions)
        {
            return CreateOptions & (WinFile.FILE_SYNCHRONOUS_IO_ALERT | WinFile.FILE_SYNCHRONOUS_IO_NONALERT);
        }

        internal static bool TryOpenPipeRelative(BinaryEmulator Instance, ulong FileHandlePtr, ulong IoStatusBlockPtr, AccessMask Permissions, ulong RootDirectory, string Name, uint CreateOptions, bool Inherit, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;
            if (!GuestNamedPipe.TryResolveRelative(Instance, RootDirectory, Name, out string GuestPath, out GuestNamedPipe Server))
                return false;

            GuestNamedPipe Client;
            if (Server != null)
                Status = GuestNamedPipe.TryCreateClientOf(Server, out Client);
            else if (GuestPath != null)
                Status = GuestNamedPipe.TryCreateClient(GuestPath, out Client);
            else
            {
                Status = NTSTATUS.STATUS_OBJECT_NAME_INVALID;
                Client = null;
            }

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return true;
            }

            Status = CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, Permissions, GuestPath, Client.HandleControl, Client, CreateOptions, Inherit);
            return true;
        }

        // NT: npfs NpFsdCreate. FileAppendData is FILE_ADD_SUBDIRECTORY, and the handle is named after the device.
        internal static bool TryOpenPipeDirectory(BinaryEmulator Instance, ulong FileHandlePtr, ulong IoStatusBlockPtr, AccessMask DesiredAccess, string Path, uint CreateDisposition, uint CreateOptions, bool Inherit, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;
            if (Path == null || !Path.Contains(Instance.WinHelper.AppContainerNamedObjects.Path, StringComparison.OrdinalIgnoreCase))
                return false;

            string DevicePath = WinSysHelper.NormalizePipePath(Path);
            if (!Instance.WinHelper.TryGetPipeDirectoryAccess(DevicePath, out AccessMask Grantable))
                return false;

            AccessMask Granted = AccessMask.None;
            if ((CreateOptions & FILE_DIRECTORY_FILE) == 0 || CreateDisposition < FILE_OPEN || CreateDisposition > FILE_OPEN_IF)
                Status = NTSTATUS.STATUS_OBJECT_NAME_INVALID;
            else if (CreateDisposition != FILE_OPEN && (Grantable & AccessMask.FileAppendData) == 0)
                Status = NTSTATUS.STATUS_ACCESS_DENIED;
            else if (CreateDisposition == FILE_CREATE)
                Status = NTSTATUS.STATUS_OBJECT_NAME_COLLISION;
            else if (!WinSysHelper.TryGrantObjectAccess(DesiredAccess, WinSysHelper.ObjectAccessKind.File, Grantable, out Granted))
                Status = NTSTATUS.STATUS_ACCESS_DENIED;

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return true;
            }

            GuestNamedPipe Prefix = GuestNamedPipe.CreatePrefix(DevicePath);
            Status = CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, Granted, GuestNamedPipe.DeviceName, Prefix.HandleControl, Prefix, CreateOptions, Inherit);
            return true;
        }

        private static bool TryGetDosVolumeDevicePath(BinaryEmulator Instance, string Path, out string DevicePath)
        {
            DevicePath = null;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');
            if (Value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase) || Value.StartsWith("\\\\.\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);
            if (Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            if (Value.Length == 2 && char.IsLetter(Value[0]) && Value[1] == ':')
            {
                DevicePath = "\\Device\\HarddiskVolume1";
                return true;
            }

            string VolumeGuidPath = Value.TrimStart('\\');
            const string VolumePrefix = "Volume{";
            if (VolumeGuidPath.StartsWith(VolumePrefix, StringComparison.OrdinalIgnoreCase))
            {
                int CloseBrace = VolumeGuidPath.IndexOf('}');
                if (CloseBrace >= VolumePrefix.Length && VolumeGuidPath.Substring(CloseBrace + 1).Trim('\\').Length == 0)
                {
                    string GuidText = VolumeGuidPath.Substring(VolumePrefix.Length, CloseBrace - VolumePrefix.Length);
                    if (GuidText.Equals(Instance.WinHelper.SyntheticVolumeGuid, StringComparison.OrdinalIgnoreCase))
                    {
                        DevicePath = "\\Device\\HarddiskVolume1";
                        return true;
                    }
                }
            }

            return false;
        }

        internal static bool ParentDirectoryExists(string Path)
        {
            string Value = NormalizeNtObjectPath(Path).Replace('/', '\\').TrimEnd('\\');
            if (Value.Length < 3 || !char.IsLetter(Value[0]) || Value[1] != ':' || Value[2] != '\\')
                return true;

            int Separator = Value.LastIndexOf('\\');
            if (Separator <= 2)
                return true;

            return WindowsFileStream.FromGuestPath(Value.Substring(0, Separator)).ExistsAsDirectory;
        }

        private static bool IsDriveRootPath(string Path)
        {
            if (string.IsNullOrWhiteSpace(Path))
                return false;

            string Value = Path.Trim().TrimEnd('\0').Replace('/', '\\');
            return Value.Length == 3 && char.IsLetter(Value[0]) && Value[1] == ':' && Value[2] == '\\';
        }

        private static string NormalizeNtObjectPath(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return string.Empty;

            string Normalized = Path.Trim().TrimEnd('\0');

            if (Normalized.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Normalized = Normalized.Substring(4);

            return Normalized;
        }

        private bool IsConsoleRelativeObject(string Path, ulong RootDirectoryHandle, BinaryEmulator Instance)
        {
            if (string.IsNullOrEmpty(Path))
                return false;

            bool IsReference = Path.Equals("\\Reference", StringComparison.OrdinalIgnoreCase) || Path.Equals("Reference", StringComparison.OrdinalIgnoreCase);
            bool IsConnect = Path.Equals("\\Connect", StringComparison.OrdinalIgnoreCase) || Path.Equals("Connect", StringComparison.OrdinalIgnoreCase);

            if (!IsReference && !IsConnect)
                return false;

            if (RootDirectoryHandle == 0)
                return false;

            ulong ConsoleHandle = Instance.WinHelper.ConsoleHandle.Handle;

            if (RootDirectoryHandle == ConsoleHandle)
                return true;

            if (Instance.WinHelper.ConsoleHandle.Handle != 0 && RootDirectoryHandle == Instance.WinHelper.ConsoleHandle.Handle)
                return true;

            return false;
        }

        private bool IsConsoleRelativeObject(string Path, uint RootDirectoryHandle, BinaryEmulator Instance)
        {
            return IsConsoleRelativeObject(Path, (ulong)RootDirectoryHandle, Instance);
        }

        private static ulong OpenConsoleObject(BinaryEmulator Instance, string Path, AccessMask DesiredAccess, bool Inherit)
        {
            string P = (Path ?? string.Empty).Trim();

            if (P.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                P = P.Substring(4);

            if (P.StartsWith("\\Device\\ConDrv\\", StringComparison.OrdinalIgnoreCase))
                P = P.Substring("\\Device\\ConDrv\\".Length);

            ConsoleObjectKind Kind;
            if (P.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) || P.Equals("CurrentIn", StringComparison.OrdinalIgnoreCase) || P.Equals("Input", StringComparison.OrdinalIgnoreCase))
                Kind = ConsoleObjectKind.Input;
            else if (P.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase) || P.Equals("CurrentOut", StringComparison.OrdinalIgnoreCase) || P.Equals("Output", StringComparison.OrdinalIgnoreCase) || P.Equals("Screen", StringComparison.OrdinalIgnoreCase))
                Kind = ConsoleObjectKind.Output;
            else
                return Instance.WinHelper.ConsoleHandle.Handle;

            AccessMask Granted = DesiredAccess != 0 ? DesiredAccess : AccessMask.GenericRead | AccessMask.GenericWrite;
            ulong Handle = Instance.WinHelper.HandleManager.AddHandle(WinSysHelper.CreateConsoleObject(Kind), Granted).Handle;
            if (Inherit)
                Instance.WinHelper.HandleManager.SetHandleFlags(Handle, ObjectHandleFlags.Inherit);

            return Handle;
        }

        private bool IsConsolePath(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return false;

            string P = Path.Trim();

            if (P.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                P = P.Substring(4);

            if (P.Equals("CONIN$", StringComparison.OrdinalIgnoreCase) || P.Equals("CONOUT$", StringComparison.OrdinalIgnoreCase))
                return true;

            if (P.StartsWith("\\Device\\ConDrv", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private static string ResolveNtPath(BinaryEmulator Instance, string NtPath, ulong RootDirectoryHandle)
        {
            if (string.IsNullOrEmpty(NtPath))
                return null;

            string Path = Instance.WinHelper.ResolveWindowsFilePath(NtPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
                return null;

            return Path;
        }
    }
}
