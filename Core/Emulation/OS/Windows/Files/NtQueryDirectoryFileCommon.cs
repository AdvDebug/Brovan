using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class NtQueryDirectoryFileCommon
    {
        private const uint SL_RESTART_SCAN = 0x01;
        private const uint SL_RETURN_SINGLE_ENTRY = 0x02;
        private const uint SL_NO_CURSOR_UPDATE = 0x10;

        public static NTSTATUS Handle(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlock, ulong FileInformation, uint Length, uint FileInformationClass, uint QueryFlags, ulong FileName)
        {
            if (IoStatusBlock == 0 || FileInformation == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(IoStatusBlock, 0x10) || !Instance.IsRegionMapped(FileInformation, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (GetHeaderSize(FileInformationClass) == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_INFO_CLASS, 0);
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }

            WinFile DirectoryHandle = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (DirectoryHandle == null || DirectoryHandle.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            string HostPath = GeneralHelper.IO.ResolveHostPath(DirectoryHandle.Path, Helpers.BinaryHelpers.BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostPath) || !Directory.Exists(HostPath))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            string Mask = ReadUnicodeString64(Instance, FileName);
            if (Mask == null)
                Mask = string.Empty;

            bool RestartScan = (QueryFlags & SL_RESTART_SCAN) != 0;
            bool ReturnSingleEntry = (QueryFlags & SL_RETURN_SINGLE_ENTRY) != 0;
            bool NoCursorUpdate = (QueryFlags & SL_NO_CURSOR_UPDATE) != 0;

            if (DirectoryHandle.DirectoryEntries == null || RestartScan || !string.Equals(DirectoryHandle.DirectoryMask ?? string.Empty, Mask, StringComparison.OrdinalIgnoreCase))
            {
                DirectoryHandle.DirectoryEntries = ScanDirectory(HostPath, Mask);
                DirectoryHandle.DirectoryIndex = 0;
                DirectoryHandle.DirectoryMask = Mask;
                Instance.TriggerEventMessage($"[+] NtQueryDirectoryFile: Enumerating directory \"{DirectoryHandle.Path}\".", LogFlags.Syscall);
            }

            if (DirectoryHandle.DirectoryIndex >= DirectoryHandle.DirectoryEntries.Count)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_NO_MORE_FILES, 0);
                return NTSTATUS.STATUS_NO_MORE_FILES;
            }

            ulong CurrentOffset = 0;
            int CurrentIndex = DirectoryHandle.DirectoryIndex;
            ulong RequiredLength = 0;
            ulong PreviousEntryOffset = ulong.MaxValue;

            while (CurrentIndex < DirectoryHandle.DirectoryEntries.Count)
            {
                ulong NewOffset = AlignUp(CurrentOffset, 8);
                WinDirectoryEntry Entry = DirectoryHandle.DirectoryEntries[CurrentIndex];
                string EntryName = Entry.Name ?? string.Empty;
                int FileNameByteLength = Encoding.Unicode.GetByteCount(EntryName);
                Span<byte> FileNameBytes = Instance.WinHelper.Shared.GetSpan((uint)FileNameByteLength);
                if (FileNameByteLength != 0)
                    Encoding.Unicode.GetBytes(EntryName.AsSpan(), FileNameBytes);

                ulong HeaderSize = GetHeaderSize(FileInformationClass);
                ulong EntrySize = HeaderSize + (ulong)FileNameBytes.Length;
                ulong EndOffset = NewOffset + EntrySize;
                RequiredLength = EndOffset;

                if (EndOffset > Length)
                {
                    if (CurrentOffset == 0)
                    {
                        Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredLength);
                        return NTSTATUS.STATUS_BUFFER_OVERFLOW;
                    }

                    break;
                }

                if (PreviousEntryOffset != ulong.MaxValue)
                    Instance._emulator.WriteMemory(FileInformation + PreviousEntryOffset, (uint)(NewOffset - PreviousEntryOffset), 4);

                WriteEntry(Instance, FileInformation + NewOffset, FileInformationClass, Entry, FileNameBytes, (uint)CurrentIndex);

                PreviousEntryOffset = NewOffset;
                CurrentOffset = EndOffset;
                CurrentIndex++;

                if (ReturnSingleEntry)
                    break;
            }

            if (!NoCursorUpdate)
                DirectoryHandle.DirectoryIndex = CurrentIndex;

            NTSTATUS Status = CurrentIndex >= DirectoryHandle.DirectoryEntries.Count ? NTSTATUS.STATUS_NO_MORE_FILES : NTSTATUS.STATUS_SUCCESS;
            ulong Information = CurrentOffset;

            if (CurrentOffset != 0)
                Status = NTSTATUS.STATUS_SUCCESS;

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, Status, Information);
            return Status;
        }

        private static ulong GetHeaderSize(uint FileInformationClass)
        {
            switch ((FILE_INFORMATION_CLASS)FileInformationClass)
            {
                case FILE_INFORMATION_CLASS.FileDirectoryInformation:
                    return 0x40;
                case FILE_INFORMATION_CLASS.FileFullDirectoryInformation:
                    return 0x44;
                case FILE_INFORMATION_CLASS.FileBothDirectoryInformation:
                    return 0x5E;
                case FILE_INFORMATION_CLASS.FileNamesInformation:
                    return 0x0C;
                default:
                    return 0;
            }
        }

        private static void WriteEntry(BinaryEmulator Instance, ulong Address, uint FileInformationClass, WinDirectoryEntry Entry, ReadOnlySpan<byte> FileNameBytes, uint FileIndex)
        {
            switch ((FILE_INFORMATION_CLASS)FileInformationClass)
            {
                case FILE_INFORMATION_CLASS.FileDirectoryInformation:
                    WriteFileDirectoryInformation(Instance, Address, Entry, FileNameBytes, FileIndex);
                    return;
                case FILE_INFORMATION_CLASS.FileFullDirectoryInformation:
                    WriteFileFullDirectoryInformation(Instance, Address, Entry, FileNameBytes, FileIndex);
                    return;
                case FILE_INFORMATION_CLASS.FileBothDirectoryInformation:
                    WriteFileBothDirectoryInformation(Instance, Address, Entry, FileNameBytes, FileIndex);
                    return;
                case FILE_INFORMATION_CLASS.FileNamesInformation:
                    WriteFileNamesInformation(Instance, Address, Entry, FileNameBytes, FileIndex);
                    return;
                default:
                    throw new NotSupportedException();
            }
        }

        private static void WriteFileDirectoryInformation(BinaryEmulator Instance, ulong Address, WinDirectoryEntry Entry, ReadOnlySpan<byte> FileNameBytes, uint FileIndex)
        {
            Instance._emulator.WriteMemory(Address + 0x00, 0u, 4);
            Instance._emulator.WriteMemory(Address + 0x04, FileIndex, 4);
            Instance._emulator.WriteMemory(Address + 0x08, (ulong)Entry.CreationTime, 8);
            Instance._emulator.WriteMemory(Address + 0x10, (ulong)Entry.LastAccessTime, 8);
            Instance._emulator.WriteMemory(Address + 0x18, (ulong)Entry.LastWriteTime, 8);
            Instance._emulator.WriteMemory(Address + 0x20, (ulong)Entry.ChangeTime, 8);
            Instance._emulator.WriteMemory(Address + 0x28, Entry.EndOfFile, 8);
            Instance._emulator.WriteMemory(Address + 0x30, Entry.AllocationSize, 8);
            Instance._emulator.WriteMemory(Address + 0x38, Entry.FileAttributes, 4);
            Instance._emulator.WriteMemory(Address + 0x3C, (uint)FileNameBytes.Length, 4);
            if (FileNameBytes.Length != 0)
                Instance._emulator.WriteMemory(Address + 0x40, FileNameBytes, (uint)FileNameBytes.Length);
        }

        private static void WriteFileFullDirectoryInformation(BinaryEmulator Instance, ulong Address, WinDirectoryEntry Entry, ReadOnlySpan<byte> FileNameBytes, uint FileIndex)
        {
            WriteFileDirectoryInformation(Instance, Address, Entry, FileNameBytes, FileIndex);
            Instance._emulator.WriteMemory(Address + 0x40, 0u, 4);
            if (FileNameBytes.Length != 0)
                Instance._emulator.WriteMemory(Address + 0x44, FileNameBytes, (uint)FileNameBytes.Length);
        }

        private static void WriteFileBothDirectoryInformation(BinaryEmulator Instance, ulong Address, WinDirectoryEntry Entry, ReadOnlySpan<byte> FileNameBytes, uint FileIndex)
        {
            WriteFileFullDirectoryInformation(Instance, Address, Entry, FileNameBytes, FileIndex);
            Instance.WinHelper.WriteByte(Address + 0x44, 0x00);
            Instance.WinHelper.WriteByte(Address + 0x45, 0x00);
            Instance.WinHelper.WriteZeroMemory(Address + 0x46, 0x18);
            if (FileNameBytes.Length != 0)
                Instance._emulator.WriteMemory(Address + 0x5E, FileNameBytes, (uint)FileNameBytes.Length);
        }

        private static void WriteFileNamesInformation(BinaryEmulator Instance, ulong Address, WinDirectoryEntry Entry, ReadOnlySpan<byte> FileNameBytes, uint FileIndex)
        {
            Instance._emulator.WriteMemory(Address + 0x00, 0u, 4);
            Instance._emulator.WriteMemory(Address + 0x04, FileIndex, 4);
            Instance._emulator.WriteMemory(Address + 0x08, (uint)FileNameBytes.Length, 4);
            if (FileNameBytes.Length != 0)
                Instance._emulator.WriteMemory(Address + 0x0C, FileNameBytes, (uint)FileNameBytes.Length);
        }

        private static List<WinDirectoryEntry> ScanDirectory(string HostPath, string Mask)
        {
            List<WinDirectoryEntry> Entries = new List<WinDirectoryEntry>();
            IEnumerable<string> FileSystemEntries;

            try
            {
                FileSystemEntries = Directory.EnumerateFileSystemEntries(HostPath);
            }
            catch
            {
                return Entries;
            }

            foreach (string CurrentPath in FileSystemEntries)
            {
                string Name = Path.GetFileName(CurrentPath);
                if (string.IsNullOrEmpty(Name))
                    continue;

                if (!MatchesMask(Name, Mask))
                    continue;

                bool IsDirectory = Directory.Exists(CurrentPath);
                FileAttributes Attributes;
                DateTime CreationUtc;
                DateTime LastAccessUtc;
                DateTime LastWriteUtc;
                ulong EndOfFile = 0;
                ulong AllocationSize = 0;

                if (IsDirectory)
                {
                    DirectoryInfo DirectoryInfo = new DirectoryInfo(CurrentPath);
                    Attributes = DirectoryInfo.Attributes;
                    CreationUtc = DirectoryInfo.CreationTimeUtc;
                    LastAccessUtc = DirectoryInfo.LastAccessTimeUtc;
                    LastWriteUtc = DirectoryInfo.LastWriteTimeUtc;
                    if ((Attributes & FileAttributes.Directory) == 0)
                        Attributes |= FileAttributes.Directory;
                }
                else
                {
                    FileInfo FileInfo = new FileInfo(CurrentPath);
                    Attributes = FileInfo.Attributes;
                    CreationUtc = FileInfo.CreationTimeUtc;
                    LastAccessUtc = FileInfo.LastAccessTimeUtc;
                    LastWriteUtc = FileInfo.LastWriteTimeUtc;
                    EndOfFile = (ulong)Math.Max(FileInfo.Length, 0);
                    AllocationSize = AlignUp(EndOfFile, 0x1000);
                }

                Entries.Add(new WinDirectoryEntry
                {
                    Name = Name,
                    EndOfFile = EndOfFile,
                    AllocationSize = AllocationSize,
                    FileAttributes = (uint)Attributes,
                    CreationTime = CreationUtc.ToFileTimeUtc(),
                    LastAccessTime = LastAccessUtc.ToFileTimeUtc(),
                    LastWriteTime = LastWriteUtc.ToFileTimeUtc(),
                    ChangeTime = LastWriteUtc.ToFileTimeUtc()
                });
            }

            Entries.Sort((A, B) => string.Compare(A.Name, B.Name, StringComparison.OrdinalIgnoreCase));
            return Entries;
        }

        private static bool MatchesMask(string Name, string Mask)
        {
            if (string.IsNullOrEmpty(Mask) || Mask == "*" || Mask == "*.*")
                return true;

            string Pattern = "^" + Regex.Escape(Mask).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            return Regex.IsMatch(Name, Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        private static string ReadUnicodeString64(BinaryEmulator Instance, ulong UnicodeString)
        {
            if (UnicodeString == 0)
                return string.Empty;

            ushort Length = Instance._emulator.ReadMemoryUShort(UnicodeString + 0x00);
            ulong Buffer = Instance._emulator.ReadMemoryULong(UnicodeString + 0x08);

            if (Length == 0 || Buffer == 0)
                return string.Empty;

            if (!Instance.IsRegionMapped(Buffer, Length))
                return string.Empty;

            Span<byte> Data = Instance.WinHelper.ReadMemorySpan(Buffer, Length);
            if (Data.Length == 0)
                return string.Empty;

            return Encoding.Unicode.GetString(Data).TrimEnd('\0');
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
    }
}
