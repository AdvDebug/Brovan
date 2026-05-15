using System;
using System.IO;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationFile : IWinSyscall
    {
        private const uint FileBasicInformationSize = 0x28;
        private const uint FileStandardInformationSize = 0x18;
        private const uint FileInternalInformationSize = 0x08;
        private const uint FileEaInformationSize = 0x04;
        private const uint FileAccessInformationSize = 0x04;
        private const uint FilePositionInformationSize = 0x08;
        private const uint FileModeInformationSize = 0x04;
        private const uint FileAlignmentInformationSize = 0x04;
        private const uint FileNetworkOpenInformationSize = 0x38;
        private const uint FileAttributeTagInformationSize = 0x08;
        private const uint FileIdInformationSize = 0x18;
        private const uint FileAllInformationFixedSize = 0x68;
        private const uint FileAllInformationNameOffset = 0x64;

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

            FILE_INFORMATION_CLASS InfoClass = (FILE_INFORMATION_CLASS)FileInformationClass;
            WinFile File = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (File == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }


            switch (InfoClass)
            {
                case FILE_INFORMATION_CLASS.FileBasicInformation:
                    return HandleFileBasicInformation(Instance, FileHandle, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileStandardInformation:
                    return HandleFileStandardInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileInternalInformation:
                    return HandleFileInternalInformation(Instance, FileHandle, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileEaInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileEaInformationSize, 0);
                case FILE_INFORMATION_CLASS.FileAccessInformation:
                    return HandleFileAccessInformation(Instance, FileHandle, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileNameInformation:
                case FILE_INFORMATION_CLASS.FileNormalizedNameInformation:
                    return HandleFileNameInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FilePositionInformation:
                    return HandleFilePositionInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileModeInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileModeInformationSize, 0);
                case FILE_INFORMATION_CLASS.FileAlignmentInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileAlignmentInformationSize, 0);
                case FILE_INFORMATION_CLASS.FileAllInformation:
                    return HandleFileAllInformation(Instance, FileHandle, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileNetworkOpenInformation:
                    return HandleFileNetworkOpenInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileAttributeTagInformation:
                    return HandleFileAttributeTagInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileIsRemoteDeviceInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileEaInformationSize, 0);
                case FILE_INFORMATION_CLASS.FileIdInformation:
                    return HandleFileIdInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                default:
                    Instance.TriggerEventMessage($"[!] NtQueryInformationFile: FileInformationClass {InfoClass} (0x{FileInformationClass:X}) not implemented.", LogFlags.Syscall);
                    Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0);
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        private static NTSTATUS HandleFileBasicInformation(BinaryEmulator Instance, ulong FileHandle, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileBasicInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (Attributes == 0)
                Attributes = FileAttributes.Normal;
            if (IsDirectory && (Attributes & FileAttributes.Directory) == 0)
                Attributes |= FileAttributes.Directory;

            Instance._emulator.WriteMemory(FileInformation + 0x00, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x18, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x20, (uint)Attributes, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x24, 0u, 4);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileBasicInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileStandardInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileStandardInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            Instance._emulator.WriteMemory(FileInformation + 0x00, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, 1u, 4);
            Instance.WinHelper.WriteByte(FileInformation + 0x14, 0x00);
            Instance.WinHelper.WriteByte(FileInformation + 0x15, IsDirectory ? (byte)0x01 : (byte)0x00);
            Instance._emulator.WriteMemory(FileInformation + 0x16, 0u, 2);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileStandardInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileInternalInformation(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileInternalInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            Instance._emulator.WriteMemory(FileInformation + 0x00, FileHandle, 8);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileInternalInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileAccessInformation(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileAccessInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            AccessMask Permissions = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);
            Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)Permissions, 4);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileAccessInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileNameInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            string RelativePath = BuildQueryName(File.Path);
            int NameByteLength = System.Text.Encoding.Unicode.GetByteCount(RelativePath);
            Span<byte> NameBytes = Instance.WinHelper.Shared.GetSpan((uint)NameByteLength);
            if (NameByteLength != 0)
                System.Text.Encoding.Unicode.GetBytes(RelativePath.AsSpan(), NameBytes);

            ulong RequiredSize = 4UL + (ulong)NameBytes.Length;

            if (Length < RequiredSize)
            {
                ulong Writable = Length >= 4 ? (ulong)Length - 4UL : 0;
                if (Length >= 4)
                    Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)NameBytes.Length, 4);
                if (Writable != 0)
                {
                    uint ToWrite = (uint)Math.Min((ulong)NameBytes.Length, Writable);
                    Instance._emulator.WriteMemory(FileInformation + 0x04, NameBytes, ToWrite);
                }
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredSize);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)NameBytes.Length, 4);
            if (NameBytes.Length != 0)
                Instance._emulator.WriteMemory(FileInformation + 0x04, NameBytes, (uint)NameBytes.Length);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFilePositionInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FilePositionInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            ulong Position = File == null || File.Position < 0 ? 0UL : unchecked((ulong)File.Position);
            Instance._emulator.WriteMemory(FileInformation + 0x00, Position, 8);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FilePositionInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileNetworkOpenInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileNetworkOpenInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (Attributes == 0)
                Attributes = FileAttributes.Normal;
            if (IsDirectory && (Attributes & FileAttributes.Directory) == 0)
                Attributes |= FileAttributes.Directory;

            Instance._emulator.WriteMemory(FileInformation + 0x00, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x18, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x20, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x28, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x30, (uint)Attributes, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x34, 0u, 4);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileNetworkOpenInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileAttributeTagInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileAttributeTagInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (Attributes == 0)
                Attributes = FileAttributes.Normal;
            if (IsDirectory && (Attributes & FileAttributes.Directory) == 0)
                Attributes |= FileAttributes.Directory;

            Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)Attributes, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x04, 0u, 4);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileAttributeTagInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileIdInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileIdInformationSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            ulong Hash = 14695981039346656037UL;
            string Path = File.Path ?? string.Empty;
            for (int i = 0; i < Path.Length; i++)
            {
                Hash ^= Path[i];
                Hash *= 1099511628211UL;
            }

            Instance._emulator.WriteMemory(FileInformation + 0x00, 0x1234ABCDu);
            Instance._emulator.WriteMemory(FileInformation + 0x08, Hash, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, 0UL, 8);

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileIdInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileAllInformation(BinaryEmulator Instance, ulong FileHandle, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            if (Length < FileAllInformationFixedSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            string RelativePath = BuildQueryName(File.Path);
            int NameByteLength = System.Text.Encoding.Unicode.GetByteCount(RelativePath);
            Span<byte> NameBytes = NameByteLength == 0 ? Span<byte>.Empty : Instance.WinHelper.Shared.GetSpan((uint)NameByteLength);
            if (NameByteLength != 0)
                System.Text.Encoding.Unicode.GetBytes(RelativePath.AsSpan(), NameBytes);

            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (Attributes == 0)
                Attributes = FileAttributes.Normal;
            if (IsDirectory && (Attributes & FileAttributes.Directory) == 0)
                Attributes |= FileAttributes.Directory;

            Instance._emulator.WriteMemory(FileInformation + 0x00, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x18, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x20, (uint)Attributes, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x24, 0u, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x28, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x30, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x38, 1u, 4);
            Instance.WinHelper.WriteByte(FileInformation + 0x3C, 0x00);
            Instance.WinHelper.WriteByte(FileInformation + 0x3D, IsDirectory ? (byte)0x01 : (byte)0x00);
            Instance._emulator.WriteMemory(FileInformation + 0x3E, 0u, 2);
            Instance._emulator.WriteMemory(FileInformation + 0x40, FileHandle, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x48, 0u, 4);
            AccessMask Permissions = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);
            Instance._emulator.WriteMemory(FileInformation + 0x4C, (uint)Permissions, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x50, 0UL, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x58, 0u, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x5C, 0u, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x60, (uint)NameByteLength, 4);

            uint WritableNameBytes = Length > FileAllInformationNameOffset ? Length - FileAllInformationNameOffset : 0;
            uint NameBytesToWrite = Math.Min((uint)NameByteLength, WritableNameBytes);
            if (NameBytesToWrite != 0)
                Instance._emulator.WriteMemory(FileInformation + FileAllInformationNameOffset, NameBytes, NameBytesToWrite);

            ulong BytesWritten = FileAllInformationNameOffset + NameBytesToWrite;
            if (NameBytesToWrite < (uint)NameByteLength)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, BytesWritten);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, BytesWritten);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFixedUlong(BinaryEmulator Instance, ulong IoStatusBlock, ulong FileInformation, uint Length, uint RequiredSize, uint Value)
        {
            if (Length < RequiredSize)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            Instance._emulator.WriteMemory(FileInformation + 0x00, Value, 4);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void GetFileMetadata(WinFile File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory)
        {
            Attributes = 0;
            CreationTime = 0;
            LastAccessTime = 0;
            LastWriteTime = 0;
            ChangeTime = 0;
            EndOfFile = 0;
            AllocationSize = 0;
            IsDirectory = false;

            if (File == null)
                return;

            if (File.Device)
            {
                Attributes = FileAttributes.Normal;
                return;
            }

            WindowsFileStream Stream = File.GetFileStream();
            string HostPath = Stream?.EffectiveReadHostPath;
            if (string.IsNullOrEmpty(HostPath))
                return;

            try
            {
                if (Directory.Exists(HostPath))
                {
                    DirectoryInfo DirectoryInfo = new DirectoryInfo(HostPath);
                    Attributes = DirectoryInfo.Attributes;
                    CreationTime = DirectoryInfo.CreationTimeUtc.ToFileTimeUtc();
                    LastAccessTime = DirectoryInfo.LastAccessTimeUtc.ToFileTimeUtc();
                    LastWriteTime = DirectoryInfo.LastWriteTimeUtc.ToFileTimeUtc();
                    ChangeTime = LastWriteTime;
                    IsDirectory = true;
                    if ((Attributes & FileAttributes.Directory) == 0)
                        Attributes |= FileAttributes.Directory;
                    return;
                }

                if (System.IO.File.Exists(HostPath))
                {
                    FileInfo FileInfo = new FileInfo(HostPath);
                    Attributes = FileInfo.Attributes;
                    CreationTime = FileInfo.CreationTimeUtc.ToFileTimeUtc();
                    LastAccessTime = FileInfo.LastAccessTimeUtc.ToFileTimeUtc();
                    LastWriteTime = FileInfo.LastWriteTimeUtc.ToFileTimeUtc();
                    ChangeTime = LastWriteTime;
                    EndOfFile = (ulong)Math.Max(FileInfo.Length, 0);
                    AllocationSize = AlignUp(EndOfFile, 0x1000);
                    if (Attributes == 0)
                        Attributes = FileAttributes.Normal;
                    return;
                }
            }
            catch
            {
            }

            Attributes = FileAttributes.Normal;
        }

        private static ulong AlignUp(ulong Value, ulong Alignment)
        {
            if (Alignment == 0)
                return Value;

            ulong Remainder = Value % Alignment;
            if (Remainder == 0)
                return Value;

            return Value + (Alignment - Remainder);
        }

        private static string BuildQueryName(string Path)
        {
            if (string.IsNullOrEmpty(Path))
                return string.Empty;

            string Value = Path.Replace('/', '\\').TrimEnd('\\', '\0');
            if (Value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                Value = Value.Substring(4);

            if (Value.Length >= 3 && char.IsLetter(Value[0]) && Value[1] == ':' && Value[2] == '\\')
                Value = Value.Substring(2);

            if (!Value.StartsWith("\\", StringComparison.Ordinal))
                Value = "\\" + Value.TrimStart('\\');

            return Value;
        }
    }
}
