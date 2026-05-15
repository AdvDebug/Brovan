using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationFile : IWinSyscall
    {
        private const uint FileBasicInformationSize = 0x28;
        private const uint FilePositionInformationSize = 0x08;
        private const uint FileModeInformationSize = 0x04;
        private const uint FileAllocationInformationSize = 0x08;
        private const uint FileEndOfFileInformationSize = 0x08;
        private const uint FileDispositionInformationSize = 0x01;
        private const uint FileDispositionInformationExSize = 0x04;
        private const uint FileRenameInformationHeaderSize = 0x14;

        private const uint FILE_DISPOSITION_DELETE = 0x00000001;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong FileHandle = Instance.ReadRegister(Registers.UC_X86_REG_R10);
            ulong IoStatusBlock = Instance.ReadRegister(Registers.UC_X86_REG_RDX);
            ulong FileInformation = Instance.ReadRegister(Registers.UC_X86_REG_R8);
            uint Length = (uint)Instance.ReadRegister(Registers.UC_X86_REG_R9);
            uint FileInformationClass = (uint)Instance.WinHelper.GetArg64(4);

            if (IoStatusBlock == 0 || FileInformation == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(IoStatusBlock, 0x10) || !Instance.IsRegionMapped(FileInformation, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (FileObj.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            FILE_INFORMATION_CLASS InfoClass = (FILE_INFORMATION_CLASS)FileInformationClass;
            switch (InfoClass)
            {
                case FILE_INFORMATION_CLASS.FileBasicInformation:
                    return HandleFileBasicInformation(Instance, FileHandle, FileObj, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileRenameInformation:
                case FILE_INFORMATION_CLASS.FileRenameInformationEx:
                    return HandleFileRenameInformation(Instance, FileHandle, FileObj, IoStatusBlock, FileInformation, Length, InfoClass == FILE_INFORMATION_CLASS.FileRenameInformationEx);
                case FILE_INFORMATION_CLASS.FileDispositionInformation:
                    return HandleFileDispositionInformation(Instance, FileHandle, FileObj, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileDispositionInformationEx:
                    return HandleFileDispositionInformationEx(Instance, FileHandle, FileObj, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FilePositionInformation:
                    return HandleFilePositionInformation(Instance, FileObj, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileModeInformation:
                    return HandleFileModeInformation(Instance, FileObj, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileAllocationInformation:
                    return HandleFileSizeInformation(Instance, FileHandle, FileObj, IoStatusBlock, FileInformation, Length, false);
                case FILE_INFORMATION_CLASS.FileEndOfFileInformation:
                    return HandleFileSizeInformation(Instance, FileHandle, FileObj, IoStatusBlock, FileInformation, Length, true);
                default:
                    Instance.TriggerEventMessage($"[!] NtSetInformationFile: FileInformationClass {InfoClass} (0x{FileInformationClass:X}) not implemented.", LogFlags.Syscall);
                    Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0);
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        private static NTSTATUS HandleFileBasicInformation(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileBasicInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            if (!HasWriteAttributesAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            long CreationTime = ReadInt64(Instance, FileInformation + 0x00);
            long LastAccessTime = ReadInt64(Instance, FileInformation + 0x08);
            long LastWriteTime = ReadInt64(Instance, FileInformation + 0x10);
            long ChangeTime = ReadInt64(Instance, FileInformation + 0x18);
            uint Attributes = ReadUInt32(Instance, FileInformation + 0x20);

            if (FileObj.Directory)
                Attributes |= (uint)FileAttributes.Directory;

            ApplyBasicInformation(FileObj, Attributes, CreationTime, LastAccessTime, LastWriteTime, ChangeTime);

            foreach (WinFile OtherFile in Instance.WinHelper.WinFiles)
            {
                if (OtherFile == null)
                    continue;

                if (!string.Equals(OtherFile.Path, FileObj.Path, StringComparison.OrdinalIgnoreCase))
                    continue;

                ApplyBasicInformation(OtherFile, Attributes, CreationTime, LastAccessTime, LastWriteTime, ChangeTime);
            }

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileBasicInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileRenameInformation(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length, bool Extended)
        {
            if (Length < FileRenameInformationHeaderSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            if (!HasDeleteAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            uint ReplaceData = ReadUInt32(Instance, FileInformation + 0x00);
            bool ReplaceIfExists = Extended ? (ReplaceData & 0x1) != 0 : (ReplaceData & 0xFF) != 0;
            ulong RootDirectory = ReadUInt64(Instance, FileInformation + 0x08);
            uint FileNameLength = ReadUInt32(Instance, FileInformation + 0x10);

            if (Length < FileRenameInformationHeaderSize + FileNameLength)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            string SourcePath = FileObj.Path ?? string.Empty;
            string TargetName = ReadUnicodeString(Instance, FileInformation + FileRenameInformationHeaderSize, FileNameLength);
            if (string.IsNullOrEmpty(TargetName))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            string TargetPath = ResolveRenameTargetPath(Instance, SourcePath, RootDirectory, TargetName);
            if (string.IsNullOrEmpty(TargetPath))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (!IsSameVolume(SourcePath, TargetPath))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_NOT_SAME_DEVICE, 0);
                return NTSTATUS.STATUS_NOT_SAME_DEVICE;
            }

            WindowsFileStream TargetStream = WindowsFileStream.FromGuestPath(TargetPath);
            bool TargetDirectoryExists = TargetStream.ExistsAsDirectory;
            bool TargetFileExists = TargetStream.ExistsAsFile;
            bool TargetExists = TargetDirectoryExists || TargetFileExists;

            if (TargetExists && ((FileObj.Directory && TargetFileExists) || (!FileObj.Directory && TargetDirectoryExists)))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (TargetExists && !ReplaceIfExists)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_OBJECT_NAME_COLLISION, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_COLLISION;
            }

            if (TargetExists && !DeleteExistingVirtualPath(TargetPath, FileObj.Directory))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (!MoveVirtualPath(SourcePath, TargetPath, FileObj.Directory))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            UpdateOpenFilePaths(Instance, SourcePath, TargetPath, FileObj.Directory);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, Length);
            Instance.TriggerEventMessage($"[+] NtSetInformationFile: Renamed '{SourcePath}' -> '{TargetPath}'.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileDispositionInformation(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileDispositionInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            if (!HasDeleteAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            Span<byte> Data = Instance.WinHelper.ReadMemorySpan(FileInformation, 1);
            if (Data.Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            FileObj.DeletePending = Data[0] != 0;
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileDispositionInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileDispositionInformationEx(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileDispositionInformationExSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            if (!HasDeleteAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            uint Flags = ReadUInt32(Instance, FileInformation + 0x00);
            FileObj.DeletePending = (Flags & FILE_DISPOSITION_DELETE) != 0;

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileDispositionInformationExSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFilePositionInformation(BinaryEmulator Instance, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FilePositionInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            long Position = ReadInt64(Instance, FileInformation + 0x00);
            if (Position < 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            FileObj.Position = Position;
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FilePositionInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileModeInformation(BinaryEmulator Instance, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileModeInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            FileObj.Mode = ReadUInt32(Instance, FileInformation + 0x00);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileModeInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileSizeInformation(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong IoStatusBlock, ulong FileInformation, uint Length, bool EndOfFile)
        {
            uint RequiredSize = EndOfFile ? FileEndOfFileInformationSize : FileAllocationInformationSize;
            if (Length < RequiredSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_FILE_IS_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;
            }

            if (!HasWriteDataAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            long Size = ReadInt64(Instance, FileInformation + 0x00);
            if (Size < 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (Size > int.MaxValue)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_NO_MEMORY, 0);
                return NTSTATUS.STATUS_NO_MEMORY;
            }

            WindowsFileStream Stream = FileObj.GetFileStream(true);
            if (Stream == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            try
            {
                Stream.SetLength(Size);
            }
            catch
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            FileObj.Real = true;
            if (FileObj.Position > Size)
                FileObj.Position = Size;

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void ApplyBasicInformation(WinFile FileObj, uint Attributes, long CreationTime, long LastAccessTime, long LastWriteTime, long ChangeTime)
        {
            if (FileObj == null)
                return;

            FileObj.HasBasicInformation = true;
            FileObj.BasicFileAttributes = Attributes;
            FileObj.BasicCreationTime = CreationTime;
            FileObj.BasicLastAccessTime = LastAccessTime;
            FileObj.BasicLastWriteTime = LastWriteTime;
            FileObj.BasicChangeTime = ChangeTime;
        }

        private static void UpdateOpenFilePaths(BinaryEmulator Instance, string SourcePath, string TargetPath, bool DirectoryRename)
        {
            if (string.IsNullOrEmpty(SourcePath) || string.IsNullOrEmpty(TargetPath))
                return;

            foreach (WinFile FileObj in Instance.WinHelper.WinFiles)
            {
                if (FileObj == null || string.IsNullOrEmpty(FileObj.Path))
                    continue;

                if (DirectoryRename)
                {
                    if (string.Equals(FileObj.Path, SourcePath, StringComparison.OrdinalIgnoreCase))
                    {
                        FileObj.Path = TargetPath;
                        continue;
                    }

                    string Prefix = SourcePath.EndsWith("\\", StringComparison.Ordinal) ? SourcePath : SourcePath + "\\";
                    if (FileObj.Path.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        string Suffix = FileObj.Path.Substring(Prefix.Length);
                        string NewPrefix = TargetPath.EndsWith("\\", StringComparison.Ordinal) ? TargetPath : TargetPath + "\\";
                        FileObj.Path = NewPrefix + Suffix;
                    }

                    continue;
                }

                if (string.Equals(FileObj.Path, SourcePath, StringComparison.OrdinalIgnoreCase))
                    FileObj.Path = TargetPath;
            }
        }

        private static bool MoveVirtualPath(string SourcePath, string TargetPath, bool DirectoryMove)
        {
            string SourceVirtual = GeneralHelper.IO.ResolveVirtualHostPath(SourcePath, BinaryFormat.PE);
            string TargetVirtual = GeneralHelper.IO.ResolveVirtualHostPath(TargetPath, BinaryFormat.PE, CreateDirectories: true);

            if (string.IsNullOrEmpty(TargetVirtual))
                return false;

            try
            {
                if (DirectoryMove)
                {
                    if (!string.IsNullOrEmpty(SourceVirtual) && Directory.Exists(SourceVirtual))
                    {
                        string Parent = Path.GetDirectoryName(TargetVirtual);
                        if (!string.IsNullOrEmpty(Parent))
                            Directory.CreateDirectory(Parent);

                        Directory.Move(SourceVirtual, TargetVirtual);
                        return true;
                    }

                    return true;
                }

                if (!string.IsNullOrEmpty(SourceVirtual) && File.Exists(SourceVirtual))
                {
                    string Parent = Path.GetDirectoryName(TargetVirtual);
                    if (!string.IsNullOrEmpty(Parent))
                        Directory.CreateDirectory(Parent);

                    File.Move(SourceVirtual, TargetVirtual);
                    return true;
                }

                WindowsFileStream SourceStream = WindowsFileStream.FromGuestPath(SourcePath);
                WindowsFileStream TargetStream = WindowsFileStream.FromGuestPath(TargetPath, true);
                byte[] Data = SourceStream.ExistsAsFile ? SourceStream.ReadAllBytes() : Array.Empty<byte>();
                TargetStream.WriteAllBytes(Data);

                DeleteExistingVirtualPath(SourcePath, false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool DeleteExistingVirtualPath(string PathValue, bool DirectoryPath)
        {
            string VirtualPath = GeneralHelper.IO.ResolveVirtualHostPath(PathValue, BinaryFormat.PE);
            if (string.IsNullOrEmpty(VirtualPath))
                return true;

            try
            {
                if (DirectoryPath)
                {
                    if (Directory.Exists(VirtualPath))
                        Directory.Delete(VirtualPath, true);
                    return true;
                }

                if (File.Exists(VirtualPath))
                    File.Delete(VirtualPath);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string ResolveRenameTargetPath(BinaryEmulator Instance, string SourcePath, ulong RootDirectoryHandle, string TargetName)
        {
            string Value = TargetName.Replace('/', '\\').TrimEnd('\0', '\r', '\n');
            if (string.IsNullOrEmpty(Value))
                return null;

            if (RootDirectoryHandle != 0)
            {
                WinFile Root = Instance.WinHelper.GetFileByHandle(RootDirectoryHandle, AccessMask.GiveTemp);
                if (Root == null || string.IsNullOrEmpty(Root.Path))
                    return null;

                string BasePath = Root.Path.EndsWith("\\", StringComparison.Ordinal) ? Root.Path : Root.Path + "\\";
                return CanonicalizeWindowsPath(BasePath + Value.TrimStart('\\'));
            }

            if (LooksAbsoluteWindowsPath(Value))
                return CanonicalizeWindowsPath(Value);

            string SourceDirectory = GetDirectoryName(SourcePath);
            if (string.IsNullOrEmpty(SourceDirectory))
                return CanonicalizeWindowsPath(Value);

            return CanonicalizeWindowsPath(SourceDirectory + "\\" + Value.TrimStart('\\'));
        }

        private static string GetDirectoryName(string PathValue)
        {
            if (string.IsNullOrEmpty(PathValue))
                return null;

            string Value = PathValue.Replace('/', '\\').TrimEnd('\\');
            int LastSlash = Value.LastIndexOf('\\');
            if (LastSlash < 0)
                return null;
            if (LastSlash == 2 && Value.Length >= 3 && Value[1] == ':')
                return Value.Substring(0, 3);
            return Value.Substring(0, LastSlash);
        }

        private static bool LooksAbsoluteWindowsPath(string PathValue)
        {
            if (string.IsNullOrEmpty(PathValue))
                return false;

            if (PathValue.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                return true;

            if (PathValue.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
                return true;

            if (PathValue.StartsWith("\\", StringComparison.Ordinal))
                return true;

            return PathValue.Length >= 3 && char.IsLetter(PathValue[0]) && PathValue[1] == ':' && PathValue[2] == '\\';
        }

        private static string CanonicalizeWindowsPath(string PathValue)
        {
            if (string.IsNullOrEmpty(PathValue))
                return null;

            string Value = PathValue.Replace('/', '\\').Trim();
            if (Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase) || Value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            if (Value.StartsWith("\\", StringComparison.Ordinal) && !(Value.Length >= 3 && char.IsLetter(Value[1]) && Value[2] == ':'))
                Value = "C:" + Value;

            if (Value.Length >= 2 && char.IsLetter(Value[0]) && Value[1] == ':')
            {
                if (Value.Length == 2)
                    Value += "\\";
                else if (Value[2] != '\\')
                    Value = Value.Substring(0, 2) + "\\" + Value.Substring(2).TrimStart('\\');
            }

            List<string> Parts = new List<string>();
            string Relative = Value.Length > 3 ? Value.Substring(3) : string.Empty;
            foreach (string Part in Relative.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (Part == ".")
                    continue;

                if (Part == "..")
                {
                    if (Parts.Count != 0)
                        Parts.RemoveAt(Parts.Count - 1);
                    continue;
                }

                Parts.Add(Part);
            }

            string Prefix = Value.Length >= 2 && Value[1] == ':' ? Value.Substring(0, 2) : "C:";
            if (Parts.Count == 0)
                return Prefix + "\\";

            return Prefix + "\\" + string.Join("\\", Parts);
        }

        private static bool IsSameVolume(string Left, string Right)
        {
            if (string.IsNullOrEmpty(Left) || string.IsNullOrEmpty(Right))
                return false;

            string LeftCanonical = CanonicalizeWindowsPath(Left);
            string RightCanonical = CanonicalizeWindowsPath(Right);
            if (string.IsNullOrEmpty(LeftCanonical) || string.IsNullOrEmpty(RightCanonical))
                return false;

            if (LeftCanonical.Length < 2 || RightCanonical.Length < 2)
                return false;

            return char.ToUpperInvariant(LeftCanonical[0]) == char.ToUpperInvariant(RightCanonical[0]);
        }

        private static bool HasWriteAttributesAccess(BinaryEmulator Instance, ulong FileHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);

            if ((Granted & AccessMask.GenericAll) == AccessMask.GenericAll)
                return true;
            if ((Granted & AccessMask.FileAllAccess) == AccessMask.FileAllAccess)
                return true;
            if ((Granted & AccessMask.FileWriteAttributes) == AccessMask.FileWriteAttributes)
                return true;
            if ((Granted & AccessMask.GenericWrite) == AccessMask.GenericWrite)
                return true;

            return false;
        }

        private static bool HasDeleteAccess(BinaryEmulator Instance, ulong FileHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);

            if ((Granted & AccessMask.GenericAll) == AccessMask.GenericAll)
                return true;
            if ((Granted & AccessMask.FileAllAccess) == AccessMask.FileAllAccess)
                return true;
            if ((Granted & AccessMask.Delete) == AccessMask.Delete)
                return true;

            return false;
        }

        private static bool HasWriteDataAccess(BinaryEmulator Instance, ulong FileHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);

            if ((Granted & AccessMask.GenericAll) == AccessMask.GenericAll)
                return true;
            if ((Granted & AccessMask.FileAllAccess) == AccessMask.FileAllAccess)
                return true;
            if ((Granted & AccessMask.FileWriteData) == AccessMask.FileWriteData)
                return true;
            if ((Granted & AccessMask.GenericWrite) == AccessMask.GenericWrite)
                return true;
            if ((Granted & AccessMask.FileAppendData) == AccessMask.FileAppendData)
                return true;

            return false;
        }

        private static uint ReadUInt32(BinaryEmulator Instance, ulong Address)
        {
            return Instance._emulator.ReadMemoryUInt(Address);
        }

        private static ulong ReadUInt64(BinaryEmulator Instance, ulong Address)
        {
            return Instance._emulator.ReadMemoryULong(Address);
        }

        private static long ReadInt64(BinaryEmulator Instance, ulong Address)
        {
            return unchecked((long)Instance._emulator.ReadMemoryULong(Address));
        }

        private static string ReadUnicodeString(BinaryEmulator Instance, ulong Address, uint Length)
        {
            if (Length == 0)
                return string.Empty;

            Span<byte> Data = Instance.WinHelper.ReadMemorySpan(Address, Length);
            if (Data.Length == 0)
                return string.Empty;

            return Encoding.Unicode.GetString(Data).TrimEnd('\0');
        }
    }
}
