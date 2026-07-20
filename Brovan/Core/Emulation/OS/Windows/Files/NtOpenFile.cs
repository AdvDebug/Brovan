using System;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenFile : IWinSyscall
    {
        private const uint FILE_DIRECTORY_FILE = 0x00000001;
        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

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

                    return NtCreateFile.CreateDeviceHandle64(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, VolumeInternalPath, VolumeHandler);
                }

                return NtCreateFile.CreateDeviceHandle64(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, VolumeDevicePath, null);
            }

            if (Instance.WinHelper.TryCreateDevice(Normalized, Array.Empty<byte>(), out string DevicePath, out WinDeviceDelegate DeviceHandler, out NTSTATUS DeviceStatus))
            {
                if (DeviceStatus != NTSTATUS.STATUS_SUCCESS)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, DeviceStatus, 0);
                    return DeviceStatus;
                }

                return NtCreateFile.CreateDeviceHandle64(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, DevicePath, DeviceHandler);
            }

            string Path = ResolveNtPath(Instance, FullName, AttributesRoot);
            if (string.IsNullOrEmpty(Path))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool IsDirectory = (OpenOptions & FILE_DIRECTORY_FILE) != 0 || Path.EndsWith("\\", StringComparison.Ordinal);

            if ((OpenOptions & FILE_NON_DIRECTORY_FILE) != 0 && IsDirectory)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            Path = Path.Replace('/', '\\').TrimEnd('\0');

            bool Exists = IsDirectory ? IsDriveRootPath(Path) || GeneralHelper.IO.DirectoryExists(Path, BinaryFormat.PE) : GeneralHelper.IO.FileExists(Path, BinaryFormat.PE);
            if (!Exists)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            WinFile FileObj = new WinFile
            {
                Path = Path,
                Device = false,
                Real = true,
                Directory = IsDirectory,
                Position = 0,
                Handler = null
            };

            Instance.WinHelper.WinFiles.Add(FileObj);

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(FileObj, (AccessMask)DesiredAccess);
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

            return Normalized.Replace('/', '\\');
        }

        private static string ResolveNtPath(BinaryEmulator Instance, string NtPath, ulong RootDirectoryHandle)
        {
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
