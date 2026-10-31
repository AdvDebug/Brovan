using System.Buffers.Binary;
using System.IO.Enumeration;
using System.Text;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class NtQueryDirectoryFileCommon
    {
        private const uint SL_RESTART_SCAN = 0x01;
        private const uint SL_RETURN_SINGLE_ENTRY = 0x02;
        private const uint SL_NO_CURSOR_UPDATE = 0x10;

        public static NTSTATUS Handle(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlock, ulong FileInformation, uint Length, uint FileInformationClass, uint QueryFlags, ulong FileName)
        {
            NTSTATUS Status = Query(Instance, FileHandle, EventHandle, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName, out bool EventReset);
            if (EventReset)
                Instance.WinHelper.SignalIoEvent(EventHandle, Status);
            return Status;
        }

        private static NTSTATUS Query(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlock, ulong FileInformation, uint Length, uint FileInformationClass, uint QueryFlags, ulong FileName, out bool EventReset)
        {
            EventReset = false;
            using GeneralHelper.IO.ProbeScope Scope = GeneralHelper.IO.BeginProbeScope();
            if (IoStatusBlock == 0 || FileInformation == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryProbeIoStatusBlock(IoStatusBlock, out NTSTATUS ProbeStatus))
                return ProbeStatus;

            if (!Instance.IsMemoryRangeMapped(FileInformation, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong ClassHeaderSize = GetHeaderSize(FileInformationClass);
            if (ClassHeaderSize == 0)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            // A buffer under the fixed part is a length error, not an overflow.
            if (Length < ClassHeaderSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            NTSTATUS Reference = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out WinFile DirectoryHandle, out AccessMask Granted);
            if (Reference != NTSTATUS.STATUS_SUCCESS)
                return Reference;

            if (!WinFile.AllowsRead(Granted))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (DirectoryHandle.RefusesApcRoutine(ApcRoutine))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (DirectoryHandle.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            NTSTATUS EventStatus = Instance.WinHelper.ReferenceIoEvent(EventHandle);
            if (EventStatus != NTSTATUS.STATUS_SUCCESS)
                return EventStatus;

            EventReset = true;

            string Mask = ReadUnicodeString64(Instance, FileName);
            if (Mask == null)
                Mask = string.Empty;

            // NT rejects "." and ".." as a search mask.
            if (Mask == "." || Mask == "..")
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_OBJECT_NAME_INVALID, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;
            }

            bool RestartScan = (QueryFlags & SL_RESTART_SCAN) != 0;
            bool ReturnSingleEntry = (QueryFlags & SL_RETURN_SINGLE_ENTRY) != 0;
            bool NoCursorUpdate = (QueryFlags & SL_NO_CURSOR_UPDATE) != 0;

            bool MaskProvided = !string.IsNullOrEmpty(Mask);
            bool MaskChanged = MaskProvided && !string.Equals(DirectoryHandle.DirectoryMask ?? string.Empty, Mask, StringComparison.OrdinalIgnoreCase);

            bool FirstQueryOfHandle = false;
            bool Restarting = RestartScan || MaskChanged;
            if (DirectoryHandle.DirectoryEntries == null || Restarting)
            {
                string GuestDirectory = DirectoryHandle.Path;
                string EffectiveMask = MaskProvided ? Mask : (DirectoryHandle.DirectoryMask ?? string.Empty);
                WindowsFileStream DirectoryStream = DirectoryHandle.GetFileStream();
                List<WinDirectoryEntry> Entries;
                using (Instance.WinHelper.LeaveKernelLock())
                    Entries = ListDirectory(GuestDirectory, EffectiveMask, DirectoryStream);

                if (Entries == null)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                    return NTSTATUS.STATUS_INVALID_HANDLE;
                }

                // A first query continues a scan that another query on the same handle started while the lock was out.
                if (Restarting || DirectoryHandle.DirectoryEntries == null)
                {
                    FirstQueryOfHandle = DirectoryHandle.DirectoryEntries == null;
                    DirectoryHandle.DirectoryEntries = Entries;
                    DirectoryHandle.DirectoryIndex = 0;
                    DirectoryHandle.DirectoryMask = EffectiveMask;
                }

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtQueryDirectoryFile: Enumerating directory \"{GuestDirectory}\".", LogFlags.Syscall);
            }

            if (DirectoryHandle.DirectoryIndex >= DirectoryHandle.DirectoryEntries.Count)
            {
                // NT answers STATUS_NO_SUCH_FILE only to the first query on a handle, not to a restarted scan.
                NTSTATUS EmptyStatus = FirstQueryOfHandle ? NTSTATUS.STATUS_NO_SUCH_FILE : NTSTATUS.STATUS_NO_MORE_FILES;
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, EmptyStatus, 0);
                Instance.WinHelper.QueueImmediateCompletion(DirectoryHandle, ApcRoutine, ApcContext, IoStatusBlock, EmptyStatus, 0);
                return EmptyStatus;
            }

            ulong CurrentOffset = 0;
            int CurrentIndex = DirectoryHandle.DirectoryIndex;
            ulong RequiredLength = 0;
            ulong PreviousEntryOffset = ulong.MaxValue;
            Span<byte> NextEntryOffset = stackalloc byte[4];

            while (CurrentIndex < DirectoryHandle.DirectoryEntries.Count)
            {
                ulong NewOffset = AlignUp(CurrentOffset, 8);
                WinDirectoryEntry Entry = DirectoryHandle.DirectoryEntries[CurrentIndex];
                string EntryName = Entry.Name ?? string.Empty;
                int NameBytes = Encoding.Unicode.GetByteCount(EntryName);

                ulong EntrySize = ClassHeaderSize + (ulong)NameBytes;
                ulong EndOffset = NewOffset + EntrySize;
                RequiredLength = EndOffset;

                if (EndOffset > Length)
                {
                    if (CurrentOffset == 0)
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredLength);
                        Instance.WinHelper.QueueImmediateCompletion(DirectoryHandle, ApcRoutine, ApcContext, IoStatusBlock, NTSTATUS.STATUS_BUFFER_OVERFLOW, RequiredLength);
                        return NTSTATUS.STATUS_BUFFER_OVERFLOW;
                    }

                    break;
                }

                Span<byte> Record = Instance.WinHelper.Shared.GetSpan(EntrySize).Slice(0, (int)EntrySize);
                Record.Clear();
                FormatEntry(Record, FileInformationClass, Entry, (uint)CurrentIndex, NameBytes);
                Encoding.Unicode.GetBytes(EntryName, Record.Slice((int)ClassHeaderSize));

                if (PreviousEntryOffset != ulong.MaxValue)
                    BinaryPrimitives.WriteUInt32LittleEndian(NextEntryOffset, (uint)(NewOffset - PreviousEntryOffset));

                if (!Instance._emulator.WriteMemory(FileInformation + NewOffset, Record) ||
                    (PreviousEntryOffset != ulong.MaxValue && !Instance._emulator.WriteMemory(FileInformation + PreviousEntryOffset, NextEntryOffset)))
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

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

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, Status, Information);
            Instance.WinHelper.QueueImmediateCompletion(DirectoryHandle, ApcRoutine, ApcContext, IoStatusBlock, Status, Information);
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
                case FILE_INFORMATION_CLASS.FileIdFullDirectoryInformation:
                    return 0x50;
                case FILE_INFORMATION_CLASS.FileIdBothDirectoryInformation:
                    return 0x68;
                default:
                    return 0;
            }
        }

        private static void FormatEntry(Span<byte> Record, uint FileInformationClass, WinDirectoryEntry Entry, uint FileIndex, int NameBytes)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x04), FileIndex);

            if ((FILE_INFORMATION_CLASS)FileInformationClass == FILE_INFORMATION_CLASS.FileNamesInformation)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x08), (uint)NameBytes);
                return;
            }

            BinaryPrimitives.WriteInt64LittleEndian(Record.Slice(0x08), Entry.CreationTime);
            BinaryPrimitives.WriteInt64LittleEndian(Record.Slice(0x10), Entry.LastAccessTime);
            BinaryPrimitives.WriteInt64LittleEndian(Record.Slice(0x18), Entry.LastWriteTime);
            BinaryPrimitives.WriteInt64LittleEndian(Record.Slice(0x20), Entry.ChangeTime);
            BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(0x28), Entry.EndOfFile);
            BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(0x30), Entry.AllocationSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x38), Entry.FileAttributes);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x3C), (uint)NameBytes);

            if ((FILE_INFORMATION_CLASS)FileInformationClass == FILE_INFORMATION_CLASS.FileIdFullDirectoryInformation)
                BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(0x48), Entry.FileId);
            else if ((FILE_INFORMATION_CLASS)FileInformationClass == FILE_INFORMATION_CLASS.FileIdBothDirectoryInformation)
                BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(0x60), Entry.FileId);
        }

        private static string CombineGuestPath(string DirectoryPath, string Name)
        {
            if (string.IsNullOrEmpty(DirectoryPath))
                return Name;

            return DirectoryPath.EndsWith("\\", StringComparison.Ordinal)
                ? DirectoryPath + Name
                : DirectoryPath + "\\" + Name;
        }

        internal static List<WinDirectoryEntry> ListDirectory(string GuestPath, string Mask, WindowsFileStream DirectoryStream)
        {
            if (IsMissingExactName(GuestPath, Mask, DirectoryStream))
                return new List<WinDirectoryEntry>();

            string HostPath = GeneralHelper.IO.ResolveHostPath(GuestPath, Helpers.BinaryHelpers.BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostPath) || !Directory.Exists(HostPath))
                return null;

            return ScanDirectory(HostPath, GeneralHelper.IO.ResolveNativeHostPath(GuestPath), Mask, GuestPath);
        }

        private static readonly char[] NotPlainNameCharacters = { '*', '?', '<', '>', '"', '\\', '/', ':' };

        // NT looks a plain name up in the directory index. Only a name that no store holds is answered here, because
        // the listing gives a found name its stored case.
        private static bool IsMissingExactName(string GuestPath, string Mask, WindowsFileStream DirectoryStream)
        {
            if (DirectoryStream == null || string.IsNullOrEmpty(Mask) || Mask == "." || Mask == ".."
                || Mask.IndexOfAny(NotPlainNameCharacters) >= 0)
                return false;

            string WriteDirectory = DirectoryStream.WriteHostPath;
            string ReadDirectory = DirectoryStream.ReadHostPath;
            string NativeDirectory = GeneralHelper.IO.ResolveNativeHostPath(GuestPath);
            bool DirectorySeen = false;

            if (!IsMissingFromStore(WriteDirectory, Mask, ref DirectorySeen))
                return false;

            if (!IsSameHostPath(ReadDirectory, WriteDirectory) && !IsMissingFromStore(ReadDirectory, Mask, ref DirectorySeen))
                return false;

            if (!IsSameHostPath(NativeDirectory, WriteDirectory) && !IsSameHostPath(NativeDirectory, ReadDirectory)
                && !IsMissingFromStore(NativeDirectory, Mask, ref DirectorySeen))
                return false;

            return DirectorySeen;
        }

        // False when the store holds the name, or when the host cannot answer by one open.
        private static bool IsMissingFromStore(string DirectoryHostPath, string Name, ref bool DirectorySeen)
        {
            if (string.IsNullOrEmpty(DirectoryHostPath))
                return true;

            // \\?\ keeps Win32 from reading the name as a device such as COM1 or stripping a trailing dot or space.
            string Candidate = Path.Combine(DirectoryHostPath, Name);
            if (GeneralHelper.IsWindows && !Candidate.StartsWith(@"\\", StringComparison.Ordinal))
                Candidate = @"\\?\" + Candidate;

            GeneralHelper.IO.HostEntryKind Kind = GeneralHelper.IO.TryOpenHostEntry(Candidate, false, out Microsoft.Win32.SafeHandles.SafeFileHandle Handle, out _);
            Handle?.Dispose();

            if (Kind == GeneralHelper.IO.HostEntryKind.Missing)
                DirectorySeen = true;

            return Kind == GeneralHelper.IO.HostEntryKind.Missing || Kind == GeneralHelper.IO.HostEntryKind.MissingPath;
        }

        private static bool IsSameHostPath(string A, string B) =>
            string.Equals(A, B, GeneralHelper.IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

        private static List<WinDirectoryEntry> ScanDirectory(string HostPath, string NativePath, string Mask, string GuestPath)
        {
            List<WinDirectoryEntry> Entries = new List<WinDirectoryEntry>();
            HashSet<string> Seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (MatchesMask(".", Mask) || MatchesMask("..", Mask))
            {
                try
                {
                    DirectoryInfo Self = new DirectoryInfo(HostPath);
                    long SelfCreation = Self.CreationTimeUtc.ToFileTimeUtc();
                    long SelfAccess = Self.LastAccessTimeUtc.ToFileTimeUtc();
                    long SelfWrite = Self.LastWriteTimeUtc.ToFileTimeUtc();
                    uint DirAttr = (uint)(FileAttributes.Directory);
                    foreach (string Dot in new[] { ".", ".." })
                    {
                        if (!MatchesMask(Dot, Mask))
                            continue;
                        Entries.Add(new WinDirectoryEntry
                        {
                            Name = Dot,
                            FileAttributes = DirAttr,
                            CreationTime = SelfCreation,
                            LastAccessTime = SelfAccess,
                            LastWriteTime = SelfWrite,
                            ChangeTime = SelfWrite,
                            FileId = WinFile.MakeFileId(CombineGuestPath(GuestPath, Dot))
                        });
                    }
                }
                catch { }
            }

            AddDirectoryContents(Entries, Seen, HostPath, Mask, GuestPath);

            // The overlay shadows the host directory rather than replacing it, so both have to be listed.
            if (!string.IsNullOrEmpty(NativePath) &&
                !string.Equals(NativePath, HostPath, StringComparison.OrdinalIgnoreCase) &&
                Directory.Exists(NativePath))
                AddDirectoryContents(Entries, Seen, NativePath, Mask, GuestPath);

            Entries.Sort((A, B) => string.Compare(A.Name, B.Name, StringComparison.OrdinalIgnoreCase));
            return Entries;
        }

        private static readonly EnumerationOptions DirectoryListing = new EnumerationOptions
        {
            AttributesToSkip = 0,
            IgnoreInaccessible = false,
        };

        private static void AddDirectoryContents(List<WinDirectoryEntry> Entries, HashSet<string> Seen, string DirectoryPath, string Mask, string GuestPath)
        {
            FileSystemEnumerable<WinDirectoryEntry> HostEntries;

            try
            {
                HostEntries = new FileSystemEnumerable<WinDirectoryEntry>(DirectoryPath, ToDirectoryEntry, DirectoryListing)
                {
                    ShouldIncludePredicate = (ref FileSystemEntry Entry) => MatchesMask(Entry.FileName, Mask)
                };
            }
            catch
            {
                return;
            }

            foreach (WinDirectoryEntry Entry in HostEntries)
            {
                if (!Seen.Add(Entry.Name))
                    continue;

                Entry.FileId = WinFile.MakeFileId(CombineGuestPath(GuestPath, Entry.Name));
                Entries.Add(Entry);
            }
        }

        private static WinDirectoryEntry ToDirectoryEntry(ref FileSystemEntry Entry)
        {
            FileAttributes Attributes = Entry.Attributes;
            ulong EndOfFile = 0;

            if (Entry.IsDirectory)
                Attributes |= FileAttributes.Directory;
            else
                EndOfFile = (ulong)Math.Max(Entry.Length, 0);

            long LastWriteTime = Entry.LastWriteTimeUtc.ToFileTime();
            return new WinDirectoryEntry
            {
                Name = Entry.FileName.ToString(),
                EndOfFile = EndOfFile,
                AllocationSize = AlignUp(EndOfFile, 0x1000),
                FileAttributes = (uint)Attributes,
                CreationTime = Entry.CreationTimeUtc.ToFileTime(),
                LastAccessTime = Entry.LastAccessTimeUtc.ToFileTime(),
                LastWriteTime = LastWriteTime,
                ChangeTime = LastWriteTime
            };
        }

        private static bool MatchesMask(ReadOnlySpan<char> Name, string Mask)
        {
            if (string.IsNullOrEmpty(Mask) || Mask == "*")
                return true;

            return FileSystemName.MatchesWin32Expression(Mask.AsSpan(), Name, ignoreCase: true);
        }

        private static string ReadUnicodeString64(BinaryEmulator Instance, ulong UnicodeString)
        {
            if (UnicodeString == 0)
                return string.Empty;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            ushort Length = Instance._emulator.ReadMemoryUShort(UnicodeString + 0x00);
            ulong Buffer = Instance.WinHelper.ReadPointer(UnicodeString + PointerSize);

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
