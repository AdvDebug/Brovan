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
        private const uint FilePipeInformationSize = 0x08;
        private const uint FilePipeLocalInformationSize = 0x28;
        private const uint FileModeInformationSize = 0x04;
        private const uint FileAlignmentInformationSize = 0x04;
        private const uint FileIoCompletionNotificationInformationSize = 0x04;
        private const uint FileNetworkOpenInformationSize = 0x38;
        private const uint FileAttributeTagInformationSize = 0x08;
        private const uint FileIdInformationSize = 0x18;
        private const uint FileStreamInformationFixedSize = 0x18;
        private const uint FileCompressionInformationSize = 0x10;
        private const uint FileStatInformationSize = 0x48;
        private const uint FileAllInformationNameOffset = 0x64;

        // ntoskrnl IopQueryOperationLength and IopQuerySetAlignmentRequirement, indexed by information class.
        private static ReadOnlySpan<byte> QueryOperationLength =>
        [
            0x00, 0x00, 0x00, 0x00, 0x28, 0x18, 0x08, 0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x04, 0x04, 0x68, 0x00, 0x00, 0x08, 0x20, 0x08, 0x28, 0x10, 0x18, 0x00, 0x10, 0x48, 0x00, 0x00,
            0x38, 0x10, 0x38, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x14, 0x0C, 0x20, 0x10,
            0x08, 0x08, 0x00, 0x01, 0x00, 0x02, 0x0C, 0x74, 0x00, 0x00, 0x08, 0x18, 0x00, 0x00, 0x24, 0x00,
            0x00, 0x00, 0x00, 0x08, 0x48, 0x00, 0x60, 0x04, 0x00, 0x00, 0x04, 0x04, 0x04, 0x68, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x00,
        ];

        private static ReadOnlySpan<byte> QuerySetAlignmentRequirement =>
        [
            0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x01, 0x08, 0x04,
            0x04, 0x04, 0x08, 0x08, 0x08, 0x04, 0x08, 0x04, 0x04, 0x04, 0x08, 0x04, 0x08, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x08, 0x04, 0x04, 0x08, 0x08, 0x08, 0x04, 0x04, 0x08, 0x08, 0x08, 0x04, 0x08, 0x08,
            0x04, 0x04, 0x08, 0x01, 0x01, 0x02, 0x08, 0x08, 0x04, 0x04, 0x04, 0x04, 0x08, 0x04, 0x08, 0x08,
            0x04, 0x04, 0x04, 0x08, 0x08, 0x08, 0x08, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x01,
        ];

        // The checks and their order follow IopValidateQueryInformationParameters in ntoskrnl.
        private static NTSTATUS ValidateParameters(BinaryEmulator Instance, ulong IoStatusBlock, ulong FileInformation, uint Length, uint FileInformationClass, bool Realigned)
        {
            if (FileInformationClass >= (uint)QueryOperationLength.Length || QueryOperationLength[(int)FileInformationClass] == 0)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (Length < QueryOperationLength[(int)FileInformationClass])
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.WinHelper.ProbeIoStatusBlock(IoStatusBlock))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Realigned)
                return NTSTATUS.STATUS_SUCCESS;

            ulong Alignment = QuerySetAlignmentRequirement[(int)FileInformationClass];
            if ((FileInformation & (Alignment - 1)) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (!NtWow64GetNativeSystemInformation.IsUserRange(FileInformation, Length) || !Instance.IsAccessible(FileInformation, Length, true))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool Wow64ForwardsClass(uint FileInformationClass) => FileInformationClass switch
        {
            4 or 5 or 6 or 7 or 8 or 9 or 14 or 16 or 17 or 18 or 21 or 22 or 23 or 24 or 25 or 26 or 28 or 29 or 32 or 33 or 34 or 35
                or 41 or 43 or 44 or 45 or 46 or 47 or 48 or 49 or 51 or 53 or 54 or 55 or 58 or 59 or 62 or 67 or 68 or 70 or 71
                or 74 or 76 or 77 or 82 => true,
            _ => false,
        };

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlock = Instance.WinHelper.GetArg(1);
            ulong FileInformation = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            uint FileInformationClass = (uint)Instance.WinHelper.GetArg(4);

            // whNtQueryInformationFile in wow64.dll realigns a misaligned buffer and forwards only the listed classes.
            bool Realigned = false;
            if (Instance.IsX86Guest)
            {
                Realigned = Length != 0 && (FileInformation & 7) != 0;
                if (Realigned && !Instance.IsAccessible(FileInformation, Length, false))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Wow64ForwardsClass(FileInformationClass))
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;
            }

            NTSTATUS Validation = ValidateParameters(Instance, IoStatusBlock, FileInformation, Length, FileInformationClass, Realigned);
            if (Validation != NTSTATUS.STATUS_SUCCESS)
                return Validation;

            FILE_INFORMATION_CLASS InfoClass = (FILE_INFORMATION_CLASS)FileInformationClass;
            NTSTATUS Reference = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out WinFile File, out AccessMask Granted);
            if (Reference != NTSTATUS.STATUS_SUCCESS)
                return Reference;

            switch (InfoClass)
            {
                case FILE_INFORMATION_CLASS.FileBasicInformation:
                    return HandleFileBasicInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileStandardInformation:
                    return HandleFileStandardInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileInternalInformation:
                    return HandleFileInternalInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileEaInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileEaInformationSize, 0);
                case FILE_INFORMATION_CLASS.FileAccessInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileAccessInformationSize, (uint)Granted);
                case FILE_INFORMATION_CLASS.FileNameInformation:
                case FILE_INFORMATION_CLASS.FileNormalizedNameInformation:
                    return HandleFileNameInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FilePositionInformation:
                    return HandleFilePositionInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileModeInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileModeInformationSize, File.Mode);
                case FILE_INFORMATION_CLASS.FileAlignmentInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileAlignmentInformationSize, 0);
                case FILE_INFORMATION_CLASS.FileIoCompletionNotificationInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileIoCompletionNotificationInformationSize, File.CompletionNotificationModes);
                case FILE_INFORMATION_CLASS.FileAllInformation:
                    return HandleFileAllInformation(Instance, File, Granted, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileNetworkOpenInformation:
                    return HandleFileNetworkOpenInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileAttributeTagInformation:
                    return HandleFileAttributeTagInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileIsRemoteDeviceInformation:
                    return HandleFixedUlong(Instance, IoStatusBlock, FileInformation, Length, FileEaInformationSize, 0);
                case FILE_INFORMATION_CLASS.FilePipeInformation:
                case FILE_INFORMATION_CLASS.FilePipeLocalInformation:
                    return HandleFilePipeInformation(Instance, File, IoStatusBlock, FileInformation, InfoClass);
                case FILE_INFORMATION_CLASS.FileIdInformation:
                    return HandleFileIdInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileAlternateNameInformation:
                    return HandleFileAlternateNameInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileStreamInformation:
                    return HandleFileStreamInformation(Instance, File, IoStatusBlock, FileInformation, Length);
                case FILE_INFORMATION_CLASS.FileCompressionInformation:
                    return HandleFileCompressionInformation(Instance, File, IoStatusBlock, FileInformation);
                case FILE_INFORMATION_CLASS.FileStatInformation:
                    return HandleFileStatInformation(Instance, File, IoStatusBlock, FileInformation);
                default:
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] NtQueryInformationFile: FileInformationClass {InfoClass} (0x{FileInformationClass:X}) not implemented.", LogFlags.Syscall);
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0);
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        private static NTSTATUS HandleFilePipeInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, FILE_INFORMATION_CLASS InfoClass)
        {
            if (!File.IsNamedPipe)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            uint Required = InfoClass == FILE_INFORMATION_CLASS.FilePipeInformation ? FilePipeInformationSize : FilePipeLocalInformationSize;
            bool HostStream = File.HostStream != HostStreamKind.None;
            if (HostStream && InfoClass == FILE_INFORMATION_CLASS.FilePipeInformation)
            {
                Instance._emulator.WriteMemory(FileInformation + 0x00, GuestNamedPipe.FILE_PIPE_BYTE_STREAM_MODE);
                Instance._emulator.WriteMemory(FileInformation + 0x04, GuestNamedPipe.FILE_PIPE_QUEUE_OPERATION);
            }
            else if (HostStream)
            {
                Span<byte> Local = stackalloc byte[(int)FilePipeLocalInformationSize];
                GuestNamedPipe.WriteHostStreamLocalInformation(Local, File.HostStream);
                Instance._emulator.WriteMemory(FileInformation, Local);
            }
            else if (InfoClass == FILE_INFORMATION_CLASS.FilePipeInformation)
            {
                Instance._emulator.WriteMemory(FileInformation + 0x00, File.Pipe.ReadMode);
                Instance._emulator.WriteMemory(FileInformation + 0x04, File.Pipe.CompletionMode);
            }
            else
            {
                Span<byte> Local = stackalloc byte[(int)FilePipeLocalInformationSize];
                File.Pipe.WriteLocalInformation(Local);
                Instance._emulator.WriteMemory(FileInformation, Local);
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, Required);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileBasicInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
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

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileBasicInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileStandardInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            Instance._emulator.WriteMemory(FileInformation + 0x00, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, 1u, 4);
            Instance.WinHelper.WriteByte(FileInformation + 0x14, 0x00);
            Instance.WinHelper.WriteByte(FileInformation + 0x15, IsDirectory ? (byte)0x01 : (byte)0x00);
            Instance._emulator.WriteMemory(FileInformation + 0x16, 0u, 2);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileStandardInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileInternalInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            Instance._emulator.WriteMemory(FileInformation + 0x00, WinFile.MakeFileId(File.Path), 8);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileInternalInformationSize);
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
                ulong Writable = (ulong)Length - 4UL;
                Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)NameBytes.Length, 4);
                if (Writable != 0)
                {
                    uint ToWrite = (uint)Math.Min((ulong)NameBytes.Length, Writable);
                    Instance._emulator.WriteMemory(FileInformation + 0x04, NameBytes, ToWrite);
                }
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredSize);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)NameBytes.Length, 4);
            if (NameBytes.Length != 0)
                Instance._emulator.WriteMemory(FileInformation + 0x04, NameBytes, (uint)NameBytes.Length);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFilePositionInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            ulong Position = File == null || File.Position < 0 ? 0UL : unchecked((ulong)File.Position);
            Instance._emulator.WriteMemory(FileInformation + 0x00, Position, 8);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FilePositionInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileNetworkOpenInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
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

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileNetworkOpenInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileAttributeTagInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (Attributes == 0)
                Attributes = FileAttributes.Normal;
            if (IsDirectory && (Attributes & FileAttributes.Directory) == 0)
                Attributes |= FileAttributes.Directory;

            Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)Attributes, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x04, 0u, 4);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileAttributeTagInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // No 8.3 table in the VFS, so the long name is also the alternate name.
        private static NTSTATUS HandleFileAlternateNameInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            string Leaf = System.IO.Path.GetFileName(File.Path ?? string.Empty);
            int NameByteLength = System.Text.Encoding.Unicode.GetByteCount(Leaf);
            ulong RequiredSize = 4UL + (ulong)NameByteLength;

            Span<byte> NameBytes = Instance.WinHelper.Shared.GetSpan((uint)NameByteLength);
            if (NameByteLength != 0)
                System.Text.Encoding.Unicode.GetBytes(Leaf.AsSpan(), NameBytes);

            Instance._emulator.WriteMemory(FileInformation + 0x00, (uint)NameByteLength, 4);
            if (Length < RequiredSize)
            {
                uint ToWrite = (uint)(Length - 4);
                if (ToWrite != 0)
                    Instance._emulator.WriteMemory(FileInformation + 0x04, NameBytes, ToWrite);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredSize);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            if (NameByteLength != 0)
                Instance._emulator.WriteMemory(FileInformation + 0x04, NameBytes, (uint)NameByteLength);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // One unnamed data stream per file, which is all the VFS stores.
        private static NTSTATUS HandleFileStreamInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
            GetFileMetadata(File, out _, out _, out _, out _, out _, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (IsDirectory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            const string StreamName = "::$DATA";
            int NameByteLength = System.Text.Encoding.Unicode.GetByteCount(StreamName);
            ulong RequiredSize = FileStreamInformationFixedSize + (ulong)NameByteLength;

            if (Length < RequiredSize)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredSize);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Span<byte> NameBytes = Instance.WinHelper.Shared.GetSpan((uint)NameByteLength);
            System.Text.Encoding.Unicode.GetBytes(StreamName.AsSpan(), NameBytes);

            Instance._emulator.WriteMemory(FileInformation + 0x00, 0u, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x04, (uint)NameByteLength, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x08, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x18, NameBytes, (uint)NameByteLength);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileCompressionInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            GetFileMetadata(File, out _, out _, out _, out _, out _, out ulong EndOfFile, out _, out _);

            Instance._emulator.WriteMemory(FileInformation + 0x00, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, (ushort)0, 2);
            Instance.WinHelper.WriteByte(FileInformation + 0x0A, 0x00);
            Instance.WinHelper.WriteByte(FileInformation + 0x0B, 0x00);
            Instance.WinHelper.WriteZeroMemory(FileInformation + 0x0C, 4);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileCompressionInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileStatInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            GetFileMetadata(File, out FileAttributes Attributes, out long CreationTime, out long LastAccessTime, out long LastWriteTime, out long ChangeTime, out ulong EndOfFile, out ulong AllocationSize, out bool IsDirectory);

            if (Attributes == 0)
                Attributes = FileAttributes.Normal;
            if (IsDirectory && (Attributes & FileAttributes.Directory) == 0)
                Attributes |= FileAttributes.Directory;

            Instance._emulator.WriteMemory(FileInformation + 0x00, WinFile.MakeFileId(File.Path), 8);
            Instance._emulator.WriteMemory(FileInformation + 0x08, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x18, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x20, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x28, AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x30, EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x38, (uint)Attributes, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x3C, 0u, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x40, 1u, 4);
            Instance._emulator.WriteMemory(FileInformation + 0x44, (uint)AccessMask.FileAllAccess, 4);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileStatInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileIdInformation(BinaryEmulator Instance, WinFile File, ulong IoStatusBlock, ulong FileInformation)
        {
            ulong Hash = WinFile.MakeFileId(File.Path);

            Instance._emulator.WriteMemory(FileInformation + 0x00, 0x1234ABCDu);
            Instance._emulator.WriteMemory(FileInformation + 0x08, Hash, 8);
            Instance._emulator.WriteMemory(FileInformation + 0x10, 0UL, 8);

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, FileIdInformationSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFileAllInformation(BinaryEmulator Instance, WinFile File, AccessMask Granted, ulong IoStatusBlock, ulong FileInformation, uint Length)
        {
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

            Span<byte> Fixed = stackalloc byte[(int)FileAllInformationNameOffset];
            Fixed.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(0x00), CreationTime);
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(0x08), LastAccessTime);
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(0x10), LastWriteTime);
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(0x18), ChangeTime);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Fixed.Slice(0x20), (uint)Attributes);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(Fixed.Slice(0x28), AllocationSize);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(Fixed.Slice(0x30), EndOfFile);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Fixed.Slice(0x38), 1u);
            Fixed[0x3D] = IsDirectory ? (byte)0x01 : (byte)0x00;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(Fixed.Slice(0x40), WinFile.MakeFileId(File.Path));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Fixed.Slice(0x4C), (uint)Granted);
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(Fixed.Slice(0x50), File.Position);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Fixed.Slice(0x58), File.Mode);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(Fixed.Slice(0x60), (uint)NameByteLength);
            Instance._emulator.WriteMemory(FileInformation, Fixed);

            uint WritableNameBytes = Length > FileAllInformationNameOffset ? Length - FileAllInformationNameOffset : 0;
            uint NameBytesToWrite = Math.Min((uint)NameByteLength, WritableNameBytes);
            if (NameBytesToWrite != 0)
                Instance._emulator.WriteMemory(FileInformation + FileAllInformationNameOffset, NameBytes, NameBytesToWrite);

            ulong BytesWritten = FileAllInformationNameOffset + NameBytesToWrite;
            if (NameBytesToWrite < (uint)NameByteLength)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, BytesWritten);
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, BytesWritten);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleFixedUlong(BinaryEmulator Instance, ulong IoStatusBlock, ulong FileInformation, uint Length, uint RequiredSize, uint Value)
        {
            if (Length < RequiredSize)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_INFO_LENGTH_MISMATCH, 0);
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            Instance._emulator.WriteMemory(FileInformation + 0x00, Value, 4);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, RequiredSize);
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
            if (Stream == null)
                return;

            if (Stream.TryGetHandleMetadata(out Attributes, out CreationTime, out LastAccessTime, out LastWriteTime, out long HandleLength))
            {
                ChangeTime = LastWriteTime;
                if ((Attributes & FileAttributes.Directory) != 0)
                {
                    IsDirectory = true;
                    return;
                }

                EndOfFile = (ulong)Math.Max(HandleLength, 0);
                AllocationSize = AlignUp(EndOfFile, 0x1000);
                if (Attributes == 0)
                    Attributes = FileAttributes.Normal;
                return;
            }

            string HostPath = Stream.EffectiveReadHostPath;
            if (string.IsNullOrEmpty(HostPath))
                return;

            try
            {
                FileInfo Info = new FileInfo(HostPath);
                if (GeneralHelper.IO.TryGetHostAttributes(Info, out FileAttributes HostAttributes))
                {
                    Attributes = HostAttributes;
                    CreationTime = Info.CreationTimeUtc.ToFileTimeUtc();
                    LastAccessTime = Info.LastAccessTimeUtc.ToFileTimeUtc();
                    LastWriteTime = Info.LastWriteTimeUtc.ToFileTimeUtc();
                    ChangeTime = LastWriteTime;

                    if ((Attributes & FileAttributes.Directory) != 0)
                    {
                        IsDirectory = true;
                        return;
                    }

                    EndOfFile = (ulong)Math.Max(Info.Length, 0);
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
