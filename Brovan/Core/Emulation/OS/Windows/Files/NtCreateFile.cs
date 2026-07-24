using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateFile : IWinSyscall
    {
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;

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


            if (IsConsoleRelativeObject(ObjectName, RootDirectoryHandle, Instance) || IsConsolePath(RawPath))
            {
                ulong HandleValue = Instance.WinHelper.ConsoleHandle.Handle;
                Instance._emulator.WriteMemory(FileHandlePtr, HandleValue);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);
                return NTSTATUS.STATUS_SUCCESS;
            }

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

            if (Instance.WinHelper.TryCreateDevice(Normalized, Ea, out string DevicePath, out WinDeviceDelegate DeviceHandler, out NTSTATUS DeviceStatus))
            {
                if (DeviceStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, DeviceStatus, 0);
                    return DeviceStatus;
                }

                return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, DevicePath, DeviceHandler);
            }

            string Path = ResolveNtPath(Instance, RawPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            return CreateRegularHandle64(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, Path, CreateDisposition, CreateOptions);
        }

        private NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint FileHandlePtr = Instance.WinHelper.GetArg32(0);
            uint DesiredAccess = Instance.WinHelper.GetArg32(1);
            uint ObjectAttributesPtr = Instance.WinHelper.GetArg32(2);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(3);
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


            if (IsConsoleRelativeObject(ObjectName, RootDirectoryHandle, Instance) || IsConsolePath(RawPath))
            {
                uint HandleValue = (uint)Instance.WinHelper.ConsoleHandle.Handle;
                Instance._emulator.WriteMemory(FileHandlePtr, HandleValue);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);
                return NTSTATUS.STATUS_SUCCESS;
            }

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

            if (Instance.WinHelper.TryCreateDevice(Normalized, Ea, out string DevicePath, out WinDeviceDelegate DeviceHandler, out NTSTATUS DeviceStatus))
            {
                if (DeviceStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, DeviceStatus, 0);
                    return DeviceStatus;
                }

                return CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, DevicePath, DeviceHandler);
            }

            string Path = ResolveNtPath(Instance, RawPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            return CreateRegularHandle32(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)DesiredAccess, Path, CreateDisposition, CreateOptions);
        }

        private static NTSTATUS CreateRegularHandle64(BinaryEmulator Instance, ulong FileHandlePtr, ulong IoStatusBlockPtr, AccessMask Permissions, string Path, uint CreateDisposition, uint CreateOptions)
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

            WindowsFileStream Stream = WindowsFileStream.FromGuestPath(Path);
            bool DirectoryExists = Stream.ExistsAsDirectory || IsDriveRootPath(Path);
            bool FileExists = Stream.ExistsAsFile;

            if (IsDirectory && FileExists)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_NOT_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_NOT_A_DIRECTORY;
            }

            if (!IsDirectory && DirectoryExists)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_IS_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;
            }

            NTSTATUS Status = PreparePathForDisposition(Path, IsDirectory, IsDirectory ? DirectoryExists : FileExists, CreateDisposition, out uint Information);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return Status;
            }

            bool FinalExists = IsDirectory ? Stream.ExistsAsDirectory : Stream.ExistsAsFile;

            WinFile FileObj = new WinFile
            {
                Path = Path,
                Device = false,
                Real = FinalExists,
                Directory = IsDirectory,
                Position = 0,
                Handler = null,
                FileStream = Stream
            };

            Instance.WinHelper.WinFiles.Add(FileObj);

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            Instance._emulator.WriteMemory(FileHandlePtr, (ulong)Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Information);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CreateRegularHandle32(BinaryEmulator Instance, uint FileHandlePtr, uint IoStatusBlockPtr, AccessMask Permissions, string Path, uint CreateDisposition, uint CreateOptions)
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

            WindowsFileStream Stream = WindowsFileStream.FromGuestPath(Path);
            bool DirectoryExists = Stream.ExistsAsDirectory || IsDriveRootPath(Path);
            bool FileExists = Stream.ExistsAsFile;

            if (IsDirectory && FileExists)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_NOT_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_NOT_A_DIRECTORY;
            }

            if (!IsDirectory && DirectoryExists)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_IS_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;
            }

            NTSTATUS Status = PreparePathForDisposition(Path, IsDirectory, IsDirectory ? DirectoryExists : FileExists, CreateDisposition, out uint Information);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return Status;
            }

            bool FinalExists = IsDirectory ? Stream.ExistsAsDirectory : Stream.ExistsAsFile;

            WinFile FileObj = new WinFile
            {
                Path = Path,
                Device = false,
                Real = FinalExists,
                Directory = IsDirectory,
                Position = 0,
                Handler = null,
                FileStream = Stream
            };

            Instance.WinHelper.WinFiles.Add(FileObj);

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            Instance._emulator.WriteMemory(FileHandlePtr, (uint)Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Information);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS PreparePathForDisposition(string Path, bool IsDirectory, bool Exists, uint CreateDisposition, out uint Information)
        {
            Information = FILE_OPENED_INFORMATION;

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

                        if (!CreateDirectory(Path))
                            return NTSTATUS.STATUS_ACCESS_DENIED;

                        Information = FILE_CREATED_INFORMATION;
                        return NTSTATUS.STATUS_SUCCESS;

                    case FILE_OPEN_IF:
                        if (!Exists)
                        {
                            if (!CreateDirectory(Path))
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
                    if (!CreateOrTruncateFile(Path))
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

                    if (!CreateOrTruncateFile(Path))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = FILE_CREATED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OPEN_IF:
                    if (!Exists)
                    {
                        if (!CreateOrTruncateFile(Path))
                            return NTSTATUS.STATUS_ACCESS_DENIED;

                        Information = FILE_CREATED_INFORMATION;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                    Information = FILE_OPENED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OVERWRITE:
                    if (!Exists)
                        return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                    if (!CreateOrTruncateFile(Path))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = FILE_OVERWRITTEN_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                case FILE_OVERWRITE_IF:
                    if (!CreateOrTruncateFile(Path))
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    Information = Exists ? FILE_OVERWRITTEN_INFORMATION : FILE_CREATED_INFORMATION;
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
        }

        private static bool CreateOrTruncateFile(string Path)
        {
            try
            {
                WindowsFileStream.FromGuestPath(Path, true).Truncate();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool CreateDirectory(string Path)
        {
            try
            {
                WindowsFileStream.FromGuestPath(Path, true).CreateDirectory();
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

        internal static NTSTATUS CreateDeviceHandle(BinaryEmulator Instance, ulong FileHandlePtr, ulong IoStatusBlockPtr, AccessMask Permissions, string InternalPath, WinDeviceDelegate Handler)
        {
            WinFile FileObj = new WinFile
            {
                Path = InternalPath,
                Device = true,
                Real = false,
                Directory = false,
                Position = 0,
                Handler = Handler
            };

            Instance.WinHelper.WinFiles.Add(FileObj);
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            Instance.WinHelper.WritePointer(FileHandlePtr, Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);
            return NTSTATUS.STATUS_SUCCESS;
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

            bool Absolute = NtPath.StartsWith("\\", StringComparison.Ordinal);

            if (!Absolute && RootDirectoryHandle != 0)
            {
                WinFile Root = Instance.WinHelper.HandleManager.GetObjectByHandle<WinFile>(RootDirectoryHandle);

                if (Root != null && !string.IsNullOrEmpty(Root.Path))
                {
                    string Base = Root.Path;
                    if (!Base.EndsWith("\\"))
                        Base += "\\";
                    return Instance.WinHelper.ResolveWindowsFilePath(Base + NtPath);
                }
            }

            string Path = Instance.WinHelper.ResolveWindowsFilePath(NtPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
                return null;

            return Path;
        }
    }
}
