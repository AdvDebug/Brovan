using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class HandleTransfer
    {
        private const byte KindPipe = 1;
        private const byte KindFile = 2;
        private const byte KindDevice = 3;
        private const byte KindConsole = 4;
        private const byte KindHostStream = 5;
        private const byte KindSection = 6;

        private const uint SecImage = 0x01000000;

        internal static bool TryWriteRecord(BinaryEmulator Instance, ulong Handle, HandleEntry Entry, out byte[] Record)
        {
            using MemoryStream Buffer = new MemoryStream();
            using (BinaryWriter Writer = new BinaryWriter(Buffer, Encoding.UTF8, true))
            {
                if (!TryWrite(Instance, Writer, Handle, Entry))
                {
                    Record = Array.Empty<byte>();
                    return false;
                }
            }

            Record = Buffer.ToArray();
            return true;
        }

        internal static NTSTATUS ApplyRecord(BinaryEmulator Instance, ReadOnlySpan<byte> Record, Placement Placement, out ulong Handle)
        {
            using BinaryReader Reader = new BinaryReader(new MemoryStream(Record.ToArray(), false), Encoding.UTF8);
            return TryApply(Instance, Instance.WinHelper, Reader, Placement, out Handle) switch
            {
                ApplyResult.Applied => NTSTATUS.STATUS_SUCCESS,
                ApplyResult.Damaged => NTSTATUS.STATUS_INVALID_PARAMETER,
                _ => NTSTATUS.STATUS_NOT_SUPPORTED,
            };
        }

        internal static bool TryWrite(BinaryEmulator Instance, BinaryWriter Writer, ulong Handle, HandleEntry Entry)
        {
            if (Entry.Object is WinSection Section)
            {
                if (Instance.WinHelper.TryShareSectionStorage(Section) && TryWriteSection(Writer, Handle, Entry, Section))
                    return true;

                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] Section handle 0x{Handle:X} has no storage another process can map.", LogFlags.Issues);
                return false;
            }

            if (Entry.Object is not WinFile File)
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] Handle 0x{Handle:X} ({Entry.Object?.ObjectType}) cannot pass to another process.", LogFlags.Issues);
                return false;
            }

            if (!TryWriteFile(Writer, Handle, Entry, File))
            {
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] File handle 0x{Handle:X} ({File.Path}) cannot pass to another process.", LogFlags.Issues);
                return false;
            }

            return true;
        }

        private static bool TryWriteFile(BinaryWriter Writer, ulong Handle, HandleEntry Entry, WinFile File)
        {
            // The child emulator shares this host console and these standard streams.
            if (File.ConsoleKind != ConsoleObjectKind.None)
            {
                WriteHeader(Writer, Handle, Entry, KindConsole);
                Writer.Write((byte)File.ConsoleKind);
                return true;
            }

            if (File.HostStream != HostStreamKind.None)
            {
                WriteHeader(Writer, Handle, Entry, KindHostStream);
                Writer.Write((byte)File.HostStream);
                return true;
            }

            if (File.Pipe != null)
            {
                GuestPipeChannel Channel = File.Pipe.Channel;
                if (Channel == null)
                    return false;

                WriteHeader(Writer, Handle, Entry, KindPipe);
                Writer.Write(File.Pipe.GuestPath ?? string.Empty);
                Writer.Write(Channel.BackingPath);
                Writer.Write(Channel.IsServer);
                Writer.Write(Channel.ConnectedGeneration);
                Writer.Write(File.Pipe.ReadMode);
                Writer.Write(File.Pipe.CompletionMode);
                Writer.Write(File.Mode);
                return true;
            }

            if (File.Device)
            {
                if (!File.IsNullDevice)
                    return false;

                WriteHeader(Writer, Handle, Entry, KindDevice);
                Writer.Write(File.Path);
                Writer.Write(File.Mode);
                return true;
            }

            if (string.IsNullOrEmpty(File.Path))
                return false;

            if (!File.TrySharePosition())
                return false;

            WriteHeader(Writer, Handle, Entry, KindFile);
            Writer.Write(File.Path);
            Writer.Write(File.Directory);
            Writer.Write(File.ShareAccess);
            Writer.Write(File.Mode);
            Writer.Write(File.SharedPosition.CellPath);
            return true;
        }

        private static bool TryWriteSection(BinaryWriter Writer, ulong Handle, HandleEntry Entry, WinSection Section)
        {
            if (Section.SharedMemoryPath == null)
                return false;

            WriteHeader(Writer, Handle, Entry, KindSection);
            Writer.Write(Section.SharedMemoryPath);
            Writer.Write(Section.Size);
            Writer.Write(Section.Protection);
            Writer.Write(Section.Attributes);
            Writer.Write(Section.Path ?? string.Empty);
            return true;
        }

        private static void WriteHeader(BinaryWriter Writer, ulong Handle, HandleEntry Entry, byte Kind)
        {
            Writer.Write(Handle);
            Writer.Write((uint)Entry.Permissions);
            Writer.Write((uint)Entry.Flags);
            Writer.Write(Kind);
        }

        internal enum Placement
        {
            // NT gives an inherited handle the value it has in the creator.
            AtRecordValue,
            NewValue,
        }

        internal enum ApplyResult
        {
            Applied,
            Refused,
            Damaged,
        }

        // A damaged record ends the reader, because the entries after it cannot be found.
        internal static ApplyResult TryApply(BinaryEmulator Emulator, WinSysHelper Helper, BinaryReader Reader, Placement Placement, out ulong Handle)
        {
            Handle = 0;
            ulong RecordHandle;
            AccessMask Access;
            ObjectHandleFlags Flags;
            IHandleObject? Object;
            try
            {
                RecordHandle = Reader.ReadUInt64();
                Access = (AccessMask)Reader.ReadUInt32();
                Flags = (ObjectHandleFlags)Reader.ReadUInt32();
                Object = ReadObject(Emulator, Helper, Reader, RecordHandle, Access);
            }
            catch (Exception Error) when (Error is EndOfStreamException || Error is IOException || Error is FormatException || Error is ArgumentException)
            {
                Utils.LogError($"[HandleTransfer] A handle record is damaged: {Error.Message}");
                return ApplyResult.Damaged;
            }

            if (Object == null)
                return ApplyResult.Refused;

            return Place(Helper, Object, RecordHandle, Access, Flags, Placement, out Handle) ? ApplyResult.Applied : ApplyResult.Refused;
        }

        // Each kind reads all of its fields before it takes anything, so a damaged record leaves nothing behind.
        private static IHandleObject? ReadObject(BinaryEmulator Emulator, WinSysHelper Helper, BinaryReader Reader, ulong Handle, AccessMask Access)
        {
            byte Kind = Reader.ReadByte();
            WinFile File;
            switch (Kind)
            {
                case KindPipe:
                {
                    string GuestPath = Reader.ReadString();
                    string BackingPath = Reader.ReadString();
                    bool Server = Reader.ReadBoolean();
                    uint Generation = Reader.ReadUInt32();
                    uint ReadMode = Reader.ReadUInt32();
                    uint CompletionMode = Reader.ReadUInt32();
                    uint Mode = Reader.ReadUInt32();

                    if (!IsPipeBacking(BackingPath) ||
                        GuestNamedPipe.TryAttach(GuestPath, BackingPath, Server, Generation, ReadMode, CompletionMode, out GuestNamedPipe Pipe) != NTSTATUS.STATUS_SUCCESS)
                    {
                        Utils.LogError($"[HandleTransfer] Pipe handle 0x{Handle:X} ({GuestPath}) could not be attached.");
                        return null;
                    }

                    File = new WinFile { Path = GuestPath, Device = true, Mode = Mode, Handler = Pipe.HandleControl, Pipe = Pipe };
                    break;
                }

                case KindConsole:
                {
                    ConsoleObjectKind Console = (ConsoleObjectKind)Reader.ReadByte();
                    if (Console != ConsoleObjectKind.Connect && Console != ConsoleObjectKind.Input && Console != ConsoleObjectKind.Output)
                        throw new FormatException($"unknown console object kind {(byte)Console}");

                    File = WinSysHelper.CreateConsoleObject(Console);
                    break;
                }

                case KindHostStream:
                {
                    HostStreamKind Stream = (HostStreamKind)Reader.ReadByte();
                    if (Stream is not (HostStreamKind.Input or HostStreamKind.Output or HostStreamKind.Error))
                        throw new FormatException($"unknown host stream kind {(byte)Stream}");

                    // Stands for this process's own stream, which may be a console here.
                    File = WinSysHelper.CreateStandardHandleFile(Stream);
                    break;
                }

                case KindDevice:
                {
                    string DevicePath = Reader.ReadString();
                    uint Mode = Reader.ReadUInt32();
                    if (!Helper.TryCreateDevice(DevicePath, null, out string InternalPath, out WinDeviceDelegate Handler, out NTSTATUS Status) || Status != NTSTATUS.STATUS_SUCCESS)
                        return null;

                    File = new WinFile { Path = InternalPath, Device = true, Mode = Mode, Handler = Handler };
                    break;
                }

                case KindFile:
                {
                    string GuestPath = Reader.ReadString();
                    bool Directory = Reader.ReadBoolean();
                    uint ShareAccess = Reader.ReadUInt32();
                    uint Mode = Reader.ReadUInt32();
                    string CellPath = Reader.ReadString();

                    WindowsFileStream Stream = WindowsFileStream.FromGuestPath(GuestPath);
                    if (Directory ? !Stream.ExistsAsDirectory : !Stream.ExistsAsFile)
                    {
                        Utils.LogError($"[HandleTransfer] File handle 0x{Handle:X} ({GuestPath}) no longer exists.");
                        return null;
                    }

                    SharedFilePosition Position = SharedFilePosition.Open(CellPath);
                    if (Position == null)
                    {
                        Utils.LogError($"[HandleTransfer] File handle 0x{Handle:X} ({GuestPath}) lost its shared position.");
                        return null;
                    }

                    File = new WinFile
                    {
                        Path = GuestPath,
                        Real = true,
                        Directory = Directory,
                        FileStream = Stream,
                        GrantedAccess = Access,
                        ShareAccess = ShareAccess,
                        Mode = Mode,
                        SharedPosition = Position,
                    };
                    break;
                }

                case KindSection:
                    return ReadSection(Emulator, Helper, Reader, Handle);

                default:
                    throw new FormatException($"unknown handle kind {Kind}");
            }

            return File;
        }

        private static WinSection? ReadSection(BinaryEmulator Emulator, WinSysHelper Helper, BinaryReader Reader, ulong Handle)
        {
            string MemoryPath = Reader.ReadString();
            ulong Size = Reader.ReadUInt64();
            uint Protection = Reader.ReadUInt32();
            uint Attributes = Reader.ReadUInt32();
            string FilePath = Reader.ReadString();

            if (Size == 0 || Size > uint.MaxValue || (Attributes & SecImage) != 0)
                throw new FormatException($"section handle 0x{Handle:X} with size 0x{Size:X} and attributes 0x{Attributes:X}");

            ulong StorageSize = Emulator.AlignToPageSize(Size);
            GuestSharedMemory Memory = GuestSharedMemory.Open(MemoryPath, StorageSize);
            string Location = Memory?.Location;
            IntPtr Storage = Helper.AdoptSessionMemory(Memory, StorageSize);
            if (Storage == IntPtr.Zero)
            {
                Utils.LogError($"[HandleTransfer] Section handle 0x{Handle:X} ({MemoryPath}) could not be mapped.");
                return null;
            }

            return Helper.CreateTransferredSection(Size, Protection, Attributes, string.IsNullOrEmpty(FilePath) ? null : FilePath, Storage, Location);
        }

        private static bool Place(WinSysHelper Helper, IHandleObject Object, ulong RecordHandle, AccessMask Access, ObjectHandleFlags Flags, Placement Placement,
            out ulong Handle)
        {
            Handle = 0;
            WinHandle? Added = Placement == Placement.AtRecordValue
                ? Helper.HandleManager.AddHandleAt(RecordHandle, Object, Access, Flags)
                : Helper.HandleManager.AddHandle(Object, Access, Flags);

            if (Added == null)
            {
                Utils.LogError($"[HandleTransfer] Handle value 0x{RecordHandle:X} is not usable here.");
                if (Object is WinFile Unplaced)
                {
                    Unplaced.Pipe?.Dispose();
                    Unplaced.ReleaseFileStream();
                    Unplaced.ReleaseSharedPosition();
                }
                else if (Object is WinSection Section)
                {
                    Helper.ReleaseSectionIfUnreferenced(Section);
                }

                return false;
            }

            if (Object is WinFile File)
            {
                Helper.WinFiles.Add(File);
                Helper.RegisterOpenFile(File);
            }

            Helper.AddWinHandle(Added);
            Handle = Added.Handle;
            return true;
        }

        // The record comes from another process, so it may only name pipes in this session.
        private static bool IsPipeBacking(string BackingPath)
        {
            if (string.IsNullOrEmpty(BackingPath))
                return false;

            string Full = Path.GetFullPath(BackingPath);
            string Root = Path.GetFullPath(GuestSession.Directory) + Path.DirectorySeparatorChar;
            return Full.StartsWith(Root, GeneralHelper.IsWindows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                Full.EndsWith(".pipe", StringComparison.Ordinal);
        }
    }
}
