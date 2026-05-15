using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Brovan.Core.Emulation.OS.Linux.Files
{
    internal class Getdents : ILinuxSyscall
    {
        private const int O_PATH = 0x200000;
        private const int LinuxDirent64NameOffset = 19;
        private readonly bool _use64;

        /// <summary>
        /// Initializes a directory entry syscall handler for the legacy or 64-bit Linux dirent layout.
        /// </summary>
        public Getdents(bool Use64 = false)
        {
            _use64 = Use64;
        }

        /// <summary>
        /// Handles getdents/getdents64 by serializing directory entries into the guest buffer.
        /// </summary>
        public void Handle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxSyscallContext Context)
        {
            ulong fd = Context.Arg0;
            ulong dirp = Context.Arg1;
            ulong count = Context.Arg2;

            if (count == 0 || count > int.MaxValue)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(fd);
            if (Entry == null)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (Entry.Object is not FileObject FileDesc)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTDIR);
                return;
            }

            if ((FileDesc.StatusFlags & O_PATH) != 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EBADF);
                return;
            }

            if (!FileDesc.IsDirectory)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.ENOTDIR);
                return;
            }

            if (!Instance.IsRegionMapped(dirp, count))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            LinuxErrno Error = TryGetDirectoryEntries(Helper, FileDesc, out List<LinuxDirectoryEntry> Entries);
            if (Error != LinuxErrno.ESUCCESS)
            {
                Helper.SetReturnValue(Instance, Context, -(long)Error);
                return;
            }

            if (FileDesc.Offset >= (ulong)Entries.Count)
            {
                Helper.SetReturnValue(Instance, Context, 0L);
                return;
            }

            Span<byte> Buffer = Helper.Shared.GetSpan(count);
            Buffer.Clear();

            int BytesWritten = 0;
            ulong EntryIndex = FileDesc.Offset;
            while (EntryIndex < (ulong)Entries.Count)
            {
                LinuxDirectoryEntry DirectoryEntry = Entries[(int)EntryIndex];
                int RecordLength = GetRecordLength(Context.Abi, DirectoryEntry.Name);
                if (RecordLength > (int)count - BytesWritten)
                    break;

                WriteRecord(Buffer, BytesWritten, Context.Abi, DirectoryEntry, EntryIndex + 1, RecordLength);
                BytesWritten += RecordLength;
                EntryIndex++;
            }

            if (BytesWritten == 0)
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EINVAL);
                return;
            }

            if (!Instance.WriteMemory(dirp, Buffer.Slice(0, BytesWritten)))
            {
                Helper.SetReturnValue(Instance, Context, -(long)LinuxErrno.EFAULT);
                return;
            }

            FileDesc.Offset = EntryIndex;
            Helper.SetReturnValue(Instance, Context, BytesWritten);
        }

        /// <summary>
        /// Builds a stable directory entry list for a host-backed or special Linux directory.
        /// </summary>
        private LinuxErrno TryGetDirectoryEntries(LinuxSyscallsHelper Helper, FileObject FileDesc, out List<LinuxDirectoryEntry> Entries)
        {
            Entries = new List<LinuxDirectoryEntry>();
            string DirectoryPath = string.IsNullOrWhiteSpace(FileDesc.Path) ? "/" : FileDesc.Path;

            AddDirectoryEntry(Entries, DirectoryPath, ".", LinuxDirectoryEntryType.Directory);
            AddDirectoryEntry(Entries, GetParentPath(DirectoryPath), "..", LinuxDirectoryEntryType.Directory);

            if (FileDesc.IsSpecialPath)
            {
                if (!Helper.SpecialPathsHandler.TryEnumerateDirectory(Helper, DirectoryPath, out List<LinuxDirectoryEntry> SpecialEntries))
                    return LinuxErrno.ENOTDIR;

                Entries.AddRange(SpecialEntries.OrderBy(Entry => Entry.Name, StringComparer.Ordinal));
                return LinuxErrno.ESUCCESS;
            }

            try
            {
                foreach (string EntryPath in Directory.EnumerateFileSystemEntries(FileDesc.HostPath).OrderBy(EntryPath => Path.GetFileName(EntryPath), StringComparer.Ordinal))
                {
                    string Name = Path.GetFileName(EntryPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                    if (string.IsNullOrEmpty(Name))
                        continue;

                    LinuxDirectoryEntryType Type = GetHostEntryType(EntryPath);
                    Entries.Add(new LinuxDirectoryEntry
                    {
                        Name = Name,
                        Inode = LinuxStatHelper.ComputeStableId(EntryPath),
                        Type = Type
                    });
                }

                return LinuxErrno.ESUCCESS;
            }
            catch (UnauthorizedAccessException)
            {
                return LinuxErrno.EACCES;
            }
            catch (DirectoryNotFoundException)
            {
                return LinuxErrno.ENOENT;
            }
            catch (PathTooLongException)
            {
                return LinuxErrno.ENAMETOOLONG;
            }
            catch (ArgumentException)
            {
                return LinuxErrno.EINVAL;
            }
            catch (NotSupportedException)
            {
                return LinuxErrno.EINVAL;
            }
            catch (IOException)
            {
                return LinuxErrno.EIO;
            }
        }

        /// <summary>
        /// Converts a host filesystem entry into a Linux dirent type.
        /// </summary>
        private static LinuxDirectoryEntryType GetHostEntryType(string PathValue)
        {
            try
            {
                FileAttributes Attributes = File.GetAttributes(PathValue);
                if ((Attributes & FileAttributes.ReparsePoint) != 0)
                    return LinuxDirectoryEntryType.SymbolicLink;

                if ((Attributes & FileAttributes.Directory) != 0)
                    return LinuxDirectoryEntryType.Directory;

                return LinuxDirectoryEntryType.RegularFile;
            }
            catch
            {
                return LinuxDirectoryEntryType.Unknown;
            }
        }

        /// <summary>
        /// Adds a synthesized directory entry with a stable inode value.
        /// </summary>
        private static void AddDirectoryEntry(List<LinuxDirectoryEntry> Entries, string PathValue, string Name, LinuxDirectoryEntryType Type)
        {
            Entries.Add(new LinuxDirectoryEntry
            {
                Name = Name,
                Inode = LinuxStatHelper.ComputeStableId(PathValue),
                Type = Type
            });
        }

        /// <summary>
        /// Gets the normalized Linux parent path for a directory entry.
        /// </summary>
        private static string GetParentPath(string PathValue)
        {
            if (string.IsNullOrEmpty(PathValue) || PathValue == "/")
                return "/";

            int Slash = PathValue.TrimEnd('/').LastIndexOf('/');
            if (Slash <= 0)
                return "/";

            return PathValue.Substring(0, Slash);
        }

        /// <summary>
        /// Gets the aligned dirent record length for the active ABI.
        /// </summary>
        private int GetRecordLength(SyscallAbi Abi, string Name)
        {
            int NameLength = Encoding.UTF8.GetByteCount(Name ?? string.Empty);
            if (_use64)
                return AlignUp(LinuxDirent64NameOffset + NameLength + 1, 8);

            int WordSize = Abi == SyscallAbi.X64 ? 8 : 4;
            int NameOffset = WordSize * 2 + 2;
            return AlignUp(NameOffset + NameLength + 2, WordSize);
        }

        /// <summary>
        /// Writes one Linux dirent record into a host buffer.
        /// </summary>
        private void WriteRecord(Span<byte> Buffer, int Offset, SyscallAbi Abi, LinuxDirectoryEntry Entry, ulong NextOffset, int RecordLength)
        {
            string Name = Entry.Name ?? string.Empty;

            if (_use64)
            {
                WriteUInt64(Buffer, Offset, Entry.Inode);
                WriteUInt64(Buffer, Offset + 8, NextOffset);
                WriteUInt16(Buffer, Offset + 16, (ushort)RecordLength);
                Buffer[Offset + 18] = (byte)Entry.Type;
                int NameBytes = Encoding.UTF8.GetBytes(Name.AsSpan(), Buffer.Slice(Offset + LinuxDirent64NameOffset, RecordLength - LinuxDirent64NameOffset));
                Buffer[Offset + LinuxDirent64NameOffset + NameBytes] = 0;
                return;
            }

            if (Abi == SyscallAbi.X64)
            {
                WriteUInt64(Buffer, Offset, Entry.Inode);
                WriteUInt64(Buffer, Offset + 8, NextOffset);
                WriteUInt16(Buffer, Offset + 16, (ushort)RecordLength);
                int NameBytes = Encoding.UTF8.GetBytes(Name.AsSpan(), Buffer.Slice(Offset + 18, RecordLength - 18));
                Buffer[Offset + 18 + NameBytes] = 0;
                Buffer[Offset + RecordLength - 1] = (byte)Entry.Type;
                return;
            }

            WriteUInt32(Buffer, Offset, (uint)Math.Min(Entry.Inode, uint.MaxValue));
            WriteUInt32(Buffer, Offset + 4, (uint)Math.Min(NextOffset, uint.MaxValue));
            WriteUInt16(Buffer, Offset + 8, (ushort)RecordLength);
            int CompatNameBytes = Encoding.UTF8.GetBytes(Name.AsSpan(), Buffer.Slice(Offset + 10, RecordLength - 10));
            Buffer[Offset + 10 + CompatNameBytes] = 0;
            Buffer[Offset + RecordLength - 1] = (byte)Entry.Type;
        }

        /// <summary>
        /// Aligns a value up to the specified power-of-two boundary.
        /// </summary>
        private static int AlignUp(int Value, int Alignment)
        {
            return (Value + Alignment - 1) & ~(Alignment - 1);
        }

        /// <summary>
        /// Writes a little-endian unsigned 16-bit value into a host buffer.
        /// </summary>
        private static void WriteUInt16(Span<byte> Buffer, int Offset, ushort Value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(Offset, 2), Value);
        }

        /// <summary>
        /// Writes a little-endian unsigned 32-bit value into a host buffer.
        /// </summary>
        private static void WriteUInt32(Span<byte> Buffer, int Offset, uint Value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        /// <summary>
        /// Writes a little-endian unsigned 64-bit value into a host buffer.
        /// </summary>
        private static void WriteUInt64(Span<byte> Buffer, int Offset, ulong Value)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }
    }
}
