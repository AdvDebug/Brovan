using System;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenFile : IWinSyscall
    {
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
        private const uint FILE_OPEN = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            using GeneralHelper.IO.ProbeScope Scope = GeneralHelper.IO.BeginProbeScope();
            ulong FileHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = Instance.WinHelper.GetArg(1);
            ulong ObjectAttributes = Instance.WinHelper.GetArg(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(3);

            uint ShareAccess = (uint)Instance.WinHelper.GetArg(4);
            uint OpenOptions = (uint)Instance.WinHelper.GetArg(5);

            if (FileHandlePtr == 0 || ObjectAttributes == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributes, out ulong AttributesRoot, out string ObjectName, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            bool Inherit = (Instance.WinHelper.ReadObjectAttributesFlags(ObjectAttributes) & WinSysHelper.OBJ_INHERIT) != 0;

            if (NtCreateFile.TryOpenPipeRelative(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, AttributesRoot, ObjectName, OpenOptions, Inherit, out NTSTATUS PipeStatus))
                return PipeStatus;

            if (string.IsNullOrEmpty(ObjectName))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            string Normalized = NormalizeNtObjectPath(FullName);

            if (TryGetDosVolumeDevicePath(Instance, Normalized, out string VolumeDevicePath))
            {
                if (Instance.WinHelper.TryCreateDevice(VolumeDevicePath, Array.Empty<byte>(), out string VolumeInternalPath, out WinDeviceDelegate VolumeHandler, out NTSTATUS VolumeStatus))
                {
                    if (VolumeStatus != NTSTATUS.STATUS_SUCCESS)
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, VolumeStatus, 0);
                        return VolumeStatus;
                    }

                    return NtCreateFile.CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, VolumeInternalPath, VolumeHandler);
                }

                return NtCreateFile.CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, VolumeDevicePath, null);
            }

            if (!NtCreateFile.IsRootRelativeName(FullName, AttributesRoot) &&
                Instance.WinHelper.TryCreateDevice(Normalized, Array.Empty<byte>(), out string DevicePath, out WinDeviceDelegate DeviceHandler, out GuestNamedPipe DevicePipe, out NTSTATUS DeviceStatus))
            {
                if (DeviceStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, DeviceStatus, 0);
                    return DeviceStatus;
                }

                return NtCreateFile.CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, DevicePath, DeviceHandler, DevicePipe, OpenOptions, Inherit);
            }

            string Path = ResolveNtPath(Instance, FullName, AttributesRoot);
            if (string.IsNullOrEmpty(Path))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            NTSTATUS Status = OpenPath(Instance, Path, (AccessMask)(uint)DesiredAccess, ShareAccess, OpenOptions, Inherit, out ulong Handle);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Instance.WinHelper.WritePointer(FileHandlePtr, Handle);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 1);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // Path is a resolved guest path.
        internal static NTSTATUS OpenPath(BinaryEmulator Instance, string Path, AccessMask DesiredAccess, uint ShareAccess, uint OpenOptions, bool Inherit, out ulong Handle)
        {
            Handle = 0;

            bool IsDirectory = (OpenOptions & FILE_DIRECTORY_FILE) != 0 || Path.EndsWith("\\", StringComparison.Ordinal);

            if ((OpenOptions & FILE_NON_DIRECTORY_FILE) != 0 && IsDirectory)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            Path = Path.Replace('/', '\\').TrimEnd('\0');

            WindowsFileStream Stream = WindowsFileStream.FromGuestPath(Path);
            Stream.OpenForLookup(NtCreateFile.WantsReadData(DesiredAccess));
            NTSTATUS Status = CheckExistingPath(Instance, Stream, Path, DesiredAccess, ShareAccess, OpenOptions, ref IsDirectory);
            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Stream.Dispose();
                return Status;
            }

            bool DeleteOnClose = (OpenOptions & NtCreateFile.FILE_DELETE_ON_CLOSE) != 0;
            WinFile FileObj = new WinFile
            {
                Path = Path,
                Device = false,
                Real = true,
                Directory = IsDirectory,
                Position = 0,
                Handler = null,
                FileStream = Stream,
                DeletePending = DeleteOnClose,
                GrantedAccess = DesiredAccess,
                ShareAccess = ShareAccess,
                Mode = NtCreateFile.ModeFromCreateOptions(OpenOptions)
            };

            Instance.WinHelper.WinFiles.Add(FileObj);
            Instance.WinHelper.RegisterOpenFile(FileObj);

            WinHandle Added = Instance.WinHelper.HandleManager.AddHandle(FileObj, DesiredAccess);
            Instance.WinHelper.AddWinHandle(Added);
            if (Inherit)
                Instance.WinHelper.HandleManager.SetHandleFlags(Added.Handle, ObjectHandleFlags.Inherit);

            Handle = Added.Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CheckExistingPath(BinaryEmulator Instance, WindowsFileStream Stream, string Path, AccessMask DesiredAccess, uint ShareAccess, uint OpenOptions, ref bool IsDirectory)
        {
            bool DirectoryExists = IsDriveRootPath(Path) || Stream.ExistsAsDirectory;

            // With neither FILE_DIRECTORY_FILE nor FILE_NON_DIRECTORY_FILE the caller takes whatever is there,
            // which is how SetFileAttributes opens a directory
            IsDirectory = IsDirectory || (DirectoryExists && (OpenOptions & FILE_NON_DIRECTORY_FILE) == 0);

            bool Exists = IsDirectory ? DirectoryExists : Stream.ExistsAsFile;
            if (!Exists)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            if ((OpenOptions & NtCreateFile.FILE_DELETE_ON_CLOSE) != 0)
            {
                if (!NtCreateFile.HasDeleteAccess(DesiredAccess))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (Stream.IsReadOnly)
                    return NTSTATUS.STATUS_CANNOT_DELETE;
            }

            if (!IsDirectory && NtCreateFile.RefusesWriteAccess(Stream, DesiredAccess, FILE_OPEN))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (!Instance.WinHelper.ShareAccessAllows(Path, DesiredAccess, ShareAccess))
                return NTSTATUS.STATUS_SHARING_VIOLATION;

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

            return Normalized.Replace('/', '\\');
        }

        private static string ResolveNtPath(BinaryEmulator Instance, string NtPath, ulong RootDirectoryHandle)
        {
            string Path = Instance.WinHelper.ResolveWindowsFilePath(NtPath, RootDirectoryHandle);
            if (string.IsNullOrEmpty(Path))
                return null;

            return Path;
        }
    }
}
