using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // True only means the request was accepted. The process reports itself in the session table under SpawnToken.
    internal delegate bool GuestHostLauncher(string HostImage, string GuestArguments, string GuestDirectory, string SessionId, uint SpawnToken, int Depth);

    // Handles and environment a new process gets from its creator, passed in a session file named by the spawn token.
    internal static class ProcessInheritance
    {
        private const uint Magic = 0x48495642;
        private const uint Version = 2;
        private const int MaxEntries = 4096;
        private const int MaxFileBytes = 4 << 20;
        private const int MaxEnvironmentBytes = 1 << 20;

        private const byte KindPipe = 1;
        private const byte KindFile = 2;
        private const byte KindDevice = 3;
        private const byte KindConsole = 4;
        private const byte KindHostStream = 5;
        private const byte KindSection = 6;

        private const uint SecImage = 0x01000000;

        internal const uint StdHandleRequestDuplicate = 1;
        internal const uint StdHandleAlwaysDuplicate = 2;

        private const ulong ParamsStandardInput64 = 0x20;
        private const ulong ParamsStandardInput32 = 0x18;
        private const ulong ParamsEnvironment64 = 0x80;
        private const ulong ParamsEnvironment32 = 0x48;
        private const ulong ParamsEnvironmentSize64 = 0x3F0;
        private const ulong ParamsEnvironmentSize32 = 0x290;

        internal static string PathFor(uint SpawnToken) => Path.Combine(GuestSession.Directory, $"inherit-{SpawnToken:x8}.bin");

        // NT: RtlCreateProcessParametersEx pads EnvironmentSize with uninitialized heap. The block ends at its first empty string.
        internal static NTSTATUS ReadEnvironment(BinaryEmulator Instance, ulong ProcessParameters, out byte[] Block)
        {
            Block = null;

            bool Is64 = Instance.WinHelper.PointerSize == 8;
            int Width = Is64 ? 8 : 4;
            Span<byte> Field = stackalloc byte[16];
            if (!Instance.ReadMemory(ProcessParameters + (Is64 ? ParamsEnvironment64 : ParamsEnvironment32), Field.Slice(0, Width)) ||
                !Instance.ReadMemory(ProcessParameters + (Is64 ? ParamsEnvironmentSize64 : ParamsEnvironmentSize32), Field.Slice(8, Width)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Environment = Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(Field) : BinaryPrimitives.ReadUInt32LittleEndian(Field);
            ulong Size = Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(Field.Slice(8)) : BinaryPrimitives.ReadUInt32LittleEndian(Field.Slice(8));
            if (Environment == 0 || Size == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (Size > MaxEnvironmentBytes)
            {
                Utils.LogError($"[ProcessInheritance] An environment block of {Size} bytes is larger than {MaxEnvironmentBytes}.");
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
            }

            int Length = (int)Size & ~1;
            byte[] Raw = ArrayPool<byte>.Shared.Rent(Length + 4);
            try
            {
                Span<byte> Data = Raw.AsSpan(0, Length + 4);
                if (!Instance.ReadMemory(Environment, Data.Slice(0, Length)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Data.Slice(Length).Clear();
                Block = Data.Slice(0, FindEnvironmentEnd(Data)).ToArray();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Raw);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static int FindEnvironmentEnd(ReadOnlySpan<byte> Block)
        {
            bool AtStart = true;
            for (int i = 0; i + 1 < Block.Length; i += 2)
            {
                if (Block[i] != 0 || Block[i + 1] != 0)
                {
                    AtStart = false;
                    continue;
                }

                if (AtStart)
                    return i + 2;

                AtStart = true;
            }

            return 0;
        }

        private static bool IsEnvironmentBlock(byte[] Block)
        {
            return Block.Length >= 2 && Block.Length <= MaxEnvironmentBytes + 4 && (Block.Length & 1) == 0 && FindEnvironmentEnd(Block) == Block.Length;
        }

        private static bool ReadStandardHandles(BinaryEmulator Instance, ulong ProcessParameters, ulong[] Std)
        {
            if (ProcessParameters == 0)
                return false;

            bool Is64 = Instance.WinHelper.PointerSize == 8;
            ulong First = ProcessParameters + (Is64 ? ParamsStandardInput64 : ParamsStandardInput32);
            Span<byte> Raw = stackalloc byte[24];
            int Bytes = Is64 ? 24 : 12;
            if (!Instance.ReadMemory(First, Raw.Slice(0, Bytes)))
                return false;

            for (int i = 0; i < 3; i++)
                Std[i] = Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(i * 8)) : BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(i * 4));

            return true;
        }

        // NT duplicates requested standard handles whether they are inheritable or not (PspCopyAndFixupParameters).
        internal static byte[] Build(BinaryEmulator Instance, ulong ProcessParameters, byte[] Environment, bool InheritHandles, List<ulong> HandleList,
            uint StdHandleState, uint StdHandleSubsystem, uint ImageSubsystem)
        {
            HandleManager Handles = Instance.WinHelper.HandleManager;
            Dictionary<ulong, HandleEntry> Chosen = new Dictionary<ulong, HandleEntry>();

            // NT answers a request only for an image of the subsystem it names (PspSetupUserProcessAddressSpace).
            if (StdHandleState == StdHandleRequestDuplicate && ImageSubsystem != StdHandleSubsystem)
                StdHandleState = 0;

            ulong[] Std = new ulong[3];
            ReadStandardHandles(Instance, ProcessParameters, Std);

            if (StdHandleState == StdHandleRequestDuplicate || StdHandleState == StdHandleAlwaysDuplicate)
            {
                if (StdHandleState == StdHandleRequestDuplicate)
                {
                    ulong OwnParameters = Instance.WinHelper.ReadPointer(Instance.PEB + (Instance.WinHelper.PointerSize == 8 ? 0x20UL : 0x10UL));
                    ReadStandardHandles(Instance, OwnParameters, Std);
                }

                for (int i = 0; i < 3; i++)
                {
                    if (Std[i] != 0 && Handles.TryGetHandle(Std[i], out HandleEntry Entry))
                        Chosen[Std[i] & ~3UL] = Entry;
                }
            }

            if (InheritHandles)
            {
                if (HandleList != null)
                {
                    foreach (ulong Listed in HandleList)
                    {
                        if (Handles.TryGetHandle(Listed, out HandleEntry Entry) && (Entry.Flags & ObjectHandleFlags.Inherit) != 0)
                            Chosen[Listed & ~3UL] = Entry;
                    }
                }
                else
                {
                    foreach (KeyValuePair<ulong, IHandleObject> Pair in Handles.SnapshotHandles())
                    {
                        if (Handles.TryGetHandle(Pair.Key, out HandleEntry Entry) && (Entry.Flags & ObjectHandleFlags.Inherit) != 0)
                            Chosen[Pair.Key] = Entry;
                    }
                }
            }

            if (Chosen.Count == 0 && Environment == null)
                return null;

            using MemoryStream Buffer = new MemoryStream();
            using BinaryWriter Writer = new BinaryWriter(Buffer, Encoding.UTF8);
            Writer.Write(Magic);
            Writer.Write(Version);
            Writer.Write(Std[0]);
            Writer.Write(Std[1]);
            Writer.Write(Std[2]);
            Writer.Write(Environment?.Length ?? 0);
            if (Environment != null)
                Writer.Write(Environment);

            long CountPosition = Buffer.Position;
            Writer.Write(0);
            int Count = 0;

            foreach (KeyValuePair<ulong, HandleEntry> Pair in Chosen)
            {
                if (Pair.Value.Object is WinSection Section)
                {
                    if (Instance.WinHelper.TryShareSectionStorage(Section) && TryWriteSection(Writer, Pair.Key, Pair.Value, Section))
                        Count++;
                    else if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[-] Section handle 0x{Pair.Key:X} has no storage another process can map.", LogFlags.Issues);

                    continue;
                }

                if (Pair.Value.Object is not WinFile File)
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[-] Handle 0x{Pair.Key:X} ({Pair.Value.Object?.ObjectType}) cannot pass to another process.", LogFlags.Issues);
                    continue;
                }

                if (!TryWriteFile(Writer, Pair.Key, Pair.Value, File))
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[-] File handle 0x{Pair.Key:X} ({File.Path}) cannot pass to another process.", LogFlags.Issues);
                    continue;
                }

                Count++;
            }

            if (Count == 0 && Environment == null)
                return null;

            Buffer.Position = CountPosition;
            Writer.Write(Count);
            return Buffer.ToArray();
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
                if (!NullDevice.IsNullDevicePath(File.Path))
                    return false;

                WriteHeader(Writer, Handle, Entry, KindDevice);
                Writer.Write(File.Path);
                Writer.Write(File.Mode);
                return true;
            }

            if (string.IsNullOrEmpty(File.Path))
                return false;

            File.SharedPosition ??= SharedFilePosition.Create(File.Position);
            if (File.SharedPosition == null)
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

        // Returns the standard handles that arrived, zero for each one this process makes itself.
        internal static ulong[] Apply(BinaryEmulator Emulator, WinSysHelper Helper)
        {
            ulong[] Arrived = new ulong[3];
            uint SpawnToken = GuestSession.SpawnToken;
            if (SpawnToken == 0)
                return Arrived;

            string RecordPath = PathFor(SpawnToken);
            byte[] Record;
            try
            {
                if (!File.Exists(RecordPath))
                    return Arrived;

                FileInfo Info = new FileInfo(RecordPath);
                Record = Info.Length <= MaxFileBytes ? File.ReadAllBytes(RecordPath) : null;
                File.Delete(RecordPath);
            }
            catch (Exception Error)
            {
                Utils.LogError($"[ProcessInheritance] Cannot read the inherited handles: {Error.Message}");
                return Arrived;
            }

            if (Record == null)
            {
                Utils.LogError("[ProcessInheritance] The inherited handle record is too large.");
                return Arrived;
            }

            ulong[] Std = new ulong[3];
            try
            {
                using BinaryReader Reader = new BinaryReader(new MemoryStream(Record), Encoding.UTF8);
                if (Reader.ReadUInt32() != Magic || Reader.ReadUInt32() != Version)
                    return Arrived;

                for (int i = 0; i < 3; i++)
                    Std[i] = Reader.ReadUInt64();

                int EnvironmentLength = Reader.ReadInt32();
                if (EnvironmentLength < 0 || EnvironmentLength > MaxEnvironmentBytes + 4)
                    return Arrived;

                if (EnvironmentLength != 0)
                {
                    byte[] Environment = Reader.ReadBytes(EnvironmentLength);
                    if (IsEnvironmentBlock(Environment))
                        Helper.InheritedEnvironment = Environment;
                    else
                        Utils.LogError("[ProcessInheritance] The inherited environment block is damaged.");
                }

                int Count = Reader.ReadInt32();
                if (Count < 0 || Count > MaxEntries)
                    return Arrived;

                for (int i = 0; i < Count; i++)
                    ApplyEntry(Emulator, Helper, Reader);
            }
            catch (Exception Error) when (Error is EndOfStreamException || Error is IOException || Error is FormatException || Error is ArgumentException)
            {
                Utils.LogError($"[ProcessInheritance] The inherited handle record is damaged: {Error.Message}");
            }

            for (int i = 0; i < 3; i++)
            {
                if (Std[i] != 0 && Helper.HandleManager.HandleExists(Std[i]))
                    Arrived[i] = Std[i];
            }

            return Arrived;
        }

        private static void ApplyEntry(BinaryEmulator Emulator, WinSysHelper Helper, BinaryReader Reader)
        {
            ulong Handle = Reader.ReadUInt64();
            AccessMask Access = (AccessMask)Reader.ReadUInt32();
            ObjectHandleFlags Flags = (ObjectHandleFlags)Reader.ReadUInt32();
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
                        Utils.LogError($"[ProcessInheritance] Pipe handle 0x{Handle:X} ({GuestPath}) could not be attached.");
                        return;
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
                    if (Stream != HostStreamKind.Input && Stream != HostStreamKind.Output)
                        throw new FormatException($"unknown host stream kind {(byte)Stream}");

                    // Stands for this process's own stream, which may be a console here.
                    File = WinSysHelper.CreateStandardHandleFile(Stream == HostStreamKind.Input ? ConsoleObjectKind.Input : ConsoleObjectKind.Output);
                    break;
                }

                case KindDevice:
                {
                    string DevicePath = Reader.ReadString();
                    uint Mode = Reader.ReadUInt32();
                    if (!Helper.TryCreateDevice(DevicePath, null, out string InternalPath, out WinDeviceDelegate Handler, out NTSTATUS Status) || Status != NTSTATUS.STATUS_SUCCESS)
                        return;

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
                        Utils.LogError($"[ProcessInheritance] File handle 0x{Handle:X} ({GuestPath}) no longer exists.");
                        return;
                    }

                    SharedFilePosition Position = SharedFilePosition.Open(CellPath);
                    if (Position == null)
                    {
                        Utils.LogError($"[ProcessInheritance] File handle 0x{Handle:X} ({GuestPath}) lost its shared position.");
                        return;
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
                    ApplySection(Emulator, Helper, Reader, Handle, Access, Flags);
                    return;

                default:
                    throw new FormatException($"unknown handle kind {Kind}");
            }

            WinHandle Added = Helper.HandleManager.AddHandleAt(Handle, File, Access, Flags);
            if (Added == null)
            {
                Utils.LogError($"[ProcessInheritance] Handle value 0x{Handle:X} is not usable here.");
                File.Pipe?.Dispose();
                File.ReleaseFileStream();
                File.ReleaseSharedPosition();
                return;
            }

            Helper.WinFiles.Add(File);
            Helper.RegisterOpenFile(File);
            Helper.AddWinHandle(Added);
        }

        private static void ApplySection(BinaryEmulator Emulator, WinSysHelper Helper, BinaryReader Reader, ulong Handle, AccessMask Access, ObjectHandleFlags Flags)
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
                Utils.LogError($"[ProcessInheritance] Section handle 0x{Handle:X} ({MemoryPath}) could not be mapped.");
                return;
            }

            if (!Helper.AddInheritedSection(Handle, Access, Flags, Size, Protection, Attributes, FilePath, Storage, Location))
                Utils.LogError($"[ProcessInheritance] Handle value 0x{Handle:X} is not usable here.");
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

    internal static class GuestProcessLauncher
    {
        // Set on hosts where the system starts the process because Environment.ProcessPath is empty.
        internal static GuestHostLauncher HostLauncher;

        private const string SpawnDepthVariable = "BROVAN_GUEST_SPAWN_DEPTH";
        private const string ParentProcessVariable = "BROVAN_PARENT_PID";
        private const string StartSuspendedVariable = "BROVAN_START_SUSPENDED";
        private const string SessionVariable = "BROVAN_SESSION_ID";
        private const string SpawnTokenVariable = "BROVAN_SPAWN_TOKEN";

        private static int _spawnCounter;
        private const int MaxSpawnDepth = 8;

        private const int MaxSessionProcesses = 6;

        private const int MaxCommandLineChars = 8000;

        private const ulong ParamsCurrentDirectory64 = 0x38;
        private const ulong ParamsImagePathName64 = 0x60;
        private const ulong ParamsCommandLine64 = 0x70;

        private const ulong ParamsCurrentDirectory32 = 0x24;
        private const ulong ParamsImagePathName32 = 0x38;
        private const ulong ParamsCommandLine32 = 0x40;

        private const int MaxStringBytes = 0x8000;

        private const int StartupTimeoutMilliseconds = 60000;
        private const int StartupPollMilliseconds = 10;

        private const int HeaderBytes = 0x400;
        private const ushort DosSignature = 0x5A4D;
        private const uint NtSignature = 0x00004550;
        private const ushort OptionalHeaderMagic32 = 0x10B;
        private const ushort OptionalHeaderMagic64 = 0x20B;

        /// <param name="InheritRecordFor">Builds the inheritance record once the image subsystem is known.</param>
        internal static bool TryLaunch(BinaryEmulator Instance, ulong ProcessParameters, string ImageNameHint, bool StartSuspended, Func<uint, byte[]> InheritRecordFor, out WinProcess Process, out SECTION_IMAGE_INFORMATION ImageInformation, out NTSTATUS Status)
        {
            string InheritPath = null;
            bool Launched = TryLaunchWithRecord(Instance, ProcessParameters, ImageNameHint, StartSuspended, InheritRecordFor, ref InheritPath, out Process, out ImageInformation, out Status);

            if (!Launched && InheritPath != null)
            {
                try
                {
                    File.Delete(InheritPath);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[GuestProcessLauncher] Cannot remove an unused handle record: {Error.Message}");
                }
            }

            return Launched;
        }

        private static bool TryLaunchWithRecord(BinaryEmulator Instance, ulong ProcessParameters, string ImageNameHint, bool StartSuspended, Func<uint, byte[]> InheritRecordFor, ref string InheritPath, out WinProcess Process, out SECTION_IMAGE_INFORMATION ImageInformation, out NTSTATUS Status)
        {
            Process = null;
            ImageInformation = default;

            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;
            string ImagePath = ReadUnicodeString(Instance, ProcessParameters + (Is64 ? ParamsImagePathName64 : ParamsImagePathName32), Is64);
            string CommandLine = ReadUnicodeString(Instance, ProcessParameters + (Is64 ? ParamsCommandLine64 : ParamsCommandLine32), Is64);
            string CurrentDirectory = ReadUnicodeString(Instance, ProcessParameters + (Is64 ? ParamsCurrentDirectory64 : ParamsCurrentDirectory32), Is64);

            if (string.IsNullOrWhiteSpace(ImagePath))
                ImagePath = ImageNameHint;

            if (string.IsNullOrWhiteSpace(ImagePath))
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!IsAcceptableImagePath(ImagePath))
            {
                Utils.LogError($"[GuestProcessLauncher] Refusing to launch {ImagePath}: unsupported path form.");
                Status = NTSTATUS.STATUS_OBJECT_PATH_SYNTAX_BAD;
                return false;
            }

            string HostImage = GeneralHelper.IO.ResolveHostPath(StripNtPrefix(ImagePath), BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostImage) || !File.Exists(HostImage))
            {
                Status = NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
                return false;
            }

            if (!TryReadImageInformation(HostImage, out ImageInformation))
            {
                Utils.LogError($"[GuestProcessLauncher] Refusing to launch {HostImage}: not a PE image.");
                Status = NTSTATUS.STATUS_INVALID_IMAGE_FORMAT;
                return false;
            }

            if ((CommandLine?.Length ?? 0) > MaxCommandLineChars || (CurrentDirectory?.Length ?? 0) > MaxCommandLineChars)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if (!TryReserveLaunchSlot(out Status))
                return false;

            int Depth = GetSpawnDepth();
            if (Depth >= MaxSpawnDepth)
            {
                Utils.LogError($"[GuestProcessLauncher] Refusing to launch {ImagePath}: spawn depth {Depth} reached.");
                Status = NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                return false;
            }

            string GuestArguments = StripArgv0(CommandLine);
            string WorkingDirectory = ResolveWorkingDirectory(CurrentDirectory, HostImage);
            uint SpawnToken = NextSpawnToken();

            byte[] InheritRecord = InheritRecordFor?.Invoke(ImageInformation.SubSystemType);
            if (InheritRecord != null)
            {
                try
                {
                    System.IO.Directory.CreateDirectory(GuestSession.Directory);
                    InheritPath = ProcessInheritance.PathFor(SpawnToken);
                    File.WriteAllBytes(InheritPath, InheritRecord);
                }
                catch (Exception Error)
                {
                    Utils.LogError($"[GuestProcessLauncher] Cannot pass the inherited handles: {Error.Message}");
                    Status = NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                    return false;
                }
            }

            Process HostProcess;

            if (HostLauncher != null)
            {
                // The guest form of the directory: the new process maps it back to a guest path.
                if (!HostLauncher(HostImage, GuestArguments, StripNtPrefix(CurrentDirectory), GuestSession.SessionId, SpawnToken, Depth + 1))
                {
                    Utils.LogError($"[GuestProcessLauncher] The host refused to launch {HostImage}.");
                    Status = NTSTATUS.STATUS_NOT_SUPPORTED;
                    return false;
                }

                HostProcess = null;
            }
            else if (!TryStartEmulator(Instance, HostImage, GuestArguments, CurrentDirectory, WorkingDirectory, SpawnToken, Depth, StartSuspended, out HostProcess))
            {
                Status = NTSTATUS.STATUS_NOT_SUPPORTED;
                return false;
            }

            if (!WaitForStartup(HostProcess, SpawnToken, out uint ProcessId, out ulong PebAddress, out ulong StartupParameters, out uint MainThreadId))
            {
                Utils.LogError($"[GuestProcessLauncher] {Path.GetFileName(HostImage)} never reached guest startup.");
                Terminate(HostProcess);
                Status = NTSTATUS.STATUS_TIMEOUT;
                return false;
            }

            const ushort MachineAmd64 = 0x8664;

            Process = new WinProcess
            {
                PID = ProcessId,
                PPID = Instance.WinHelper.PID,
                Name = Path.GetFileName(HostImage),
                Path = ImagePath,
                HostImagePath = HostImage,
                Arch = ImageInformation.Machine == MachineAmd64 ? BinaryArchitecture.x64 : BinaryArchitecture.x86,
                CreationTime = Instance.GetEmulatedSystemTimeFileTimeUtc(),
                RunningUser = Instance.WinHelper.CurrentUser,
                MainThreadId = MainThreadId,
                ImageInformation = ImageInformation,
                Remote = RemoteGuestProcess.Adopt(ProcessId, HostProcess, Instance, PebAddress, StartupParameters),
            };

            Instance.WinHelper.ClaimProcessId(ProcessId);
            if (MainThreadId != 0)
                Instance.WinHelper.ClaimProcessId(MainThreadId);

            Instance.TriggerEventMessage($"[GuestProcessLauncher] Launched {Process.Name} as guest process {Process.PID} (depth {Depth + 1}).", LogFlags.Syscall);

            Status = NTSTATUS.STATUS_SUCCESS;
            return true;
        }

        // Under "dotnet Brovan.dll" the process path is the shared runtime host, so a child needs the
        // managed assembly to lead its arguments. Only that host sits outside the base directory, which
        // is the test; argv[0] names the assembly for an apphost build as well.
        private static string GetManagedEntryForSharedHost(string HostExecutable)
        {
            string HostDirectory = Path.GetDirectoryName(HostExecutable);
            if (string.IsNullOrEmpty(HostDirectory)) return null;

            StringComparison Comparison = GeneralHelper.IsWindows
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            if (string.Equals(Path.TrimEndingDirectorySeparator(HostDirectory),
                    Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory), Comparison))
                return null;

            string[] Arguments = Environment.GetCommandLineArgs();
            if (Arguments.Length == 0) return null;

            string Entry = Arguments[0];
            if (string.IsNullOrEmpty(Entry) || !Entry.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                return null;

            return Path.IsPathRooted(Entry)
                ? Entry
                : Path.Combine(AppContext.BaseDirectory, Path.GetFileName(Entry));
        }

        private static bool TryStartEmulator(
            BinaryEmulator Instance,
            string HostImage,
            string GuestArguments,
            string CurrentDirectory,
            string WorkingDirectory,
            uint SpawnToken,
            int Depth,
            bool StartSuspended,
            out Process HostProcess)
        {
            HostProcess = null;

            string HostExecutable = Environment.ProcessPath;
            if (string.IsNullOrEmpty(HostExecutable))
                return false;

            ProcessStartInfo StartInfo = new ProcessStartInfo
            {
                FileName = HostExecutable,
                UseShellExecute = false,
                WorkingDirectory = WorkingDirectory,
                CreateNoWindow = Utils.SilentMode && GeneralHelper.ChildConsoleOpensWindow(),
            };

            string ManagedEntry = GetManagedEntryForSharedHost(HostExecutable);
            if (ManagedEntry != null)
                StartInfo.ArgumentList.Add(ManagedEntry);

            AppendEmulatorOptions(Instance, StartInfo.ArgumentList);

            if (!string.IsNullOrEmpty(GuestArguments))
            {
                StartInfo.ArgumentList.Add("--guest-cmdline");
                StartInfo.ArgumentList.Add(Encode(GuestArguments));
            }

            if (!string.IsNullOrWhiteSpace(CurrentDirectory))
            {
                StartInfo.ArgumentList.Add("--cwd");
                StartInfo.ArgumentList.Add(Encode(StripNtPrefix(CurrentDirectory)));
            }

            StartInfo.ArgumentList.Add(HostImage);
            StartInfo.Environment[SpawnDepthVariable] = (Depth + 1).ToString();
            StartInfo.Environment[SessionVariable] = GuestSession.SessionId;
            StartInfo.Environment[SpawnTokenVariable] = SpawnToken.ToString();
            StartInfo.Environment[ParentProcessVariable] = Instance.WinHelper.PID.ToString();

            // The child inherits this emulator's environment, so a suspended process must clear the request
            // again or every process it goes on to spawn starts held as well.
            if (StartSuspended)
                StartInfo.Environment[StartSuspendedVariable] = "1";
            else
                StartInfo.Environment.Remove(StartSuspendedVariable);

            try
            {
                HostProcess = System.Diagnostics.Process.Start(StartInfo);
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[GuestProcessLauncher] Failed to launch {HostImage}: {Ex.Message}");
                return false;
            }

            return HostProcess != null;
        }

        // Only has to be unique among the live members of one session.
        private static uint NextSpawnToken()
        {
            uint Token = unchecked((uint)((Environment.ProcessId << 8) + Interlocked.Increment(ref _spawnCounter)));
            return Token == 0 ? 1u : Token;
        }

        /// <summary>
        /// The child only owns a PEB and answers cross-process requests once its emulator booted, and the creating
        /// kernel32 uses both as soon as this returns. Windows hands back an address space that already exists.
        /// </summary>
        private static bool WaitForStartup(Process HostProcess, uint SpawnToken, out uint ProcessId, out ulong PebAddress, out ulong StartupParameters, out uint MainThreadId)
        {
            long Deadline = Environment.TickCount64 + StartupTimeoutMilliseconds;

            while (true)
            {
                if (GuestSession.TryResolveSpawn(SpawnToken, out ProcessId, out _, out PebAddress, out StartupParameters, out MainThreadId))
                    return true;

                if ((HostProcess != null && HostProcess.HasExited) || Environment.TickCount64 >= Deadline)
                {
                    ProcessId = 0;
                    PebAddress = 0;
                    StartupParameters = 0;
                    MainThreadId = 0;
                    return false;
                }

                Thread.Sleep(StartupPollMilliseconds);
            }
        }

        private static void Terminate(Process HostProcess)
        {
            if (HostProcess == null)
                return;

            try
            {
                if (!HostProcess.HasExited)
                    HostProcess.Kill();
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[GuestProcessLauncher] Failed to stop host process {HostProcess.Id}: {Ex.Message}");
            }
        }

        private static string ResolveWorkingDirectory(string RequestedDirectory, string HostImage)
        {
            if (!string.IsNullOrWhiteSpace(RequestedDirectory))
            {
                string Resolved = GeneralHelper.IO.ResolveHostPath(StripNtPrefix(RequestedDirectory), BinaryFormat.PE);
                if (!string.IsNullOrEmpty(Resolved) && Directory.Exists(Resolved))
                    return Resolved;
            }

            return Path.GetDirectoryName(HostImage) ?? Environment.CurrentDirectory;
        }

        private static void AppendEmulatorOptions(BinaryEmulator Instance, System.Collections.ObjectModel.Collection<string> Arguments)
        {
            string Backend = Instance.Settings.BackendKind switch
            {
                EmulationBackendKind.Whp => "whp",
                EmulationBackendKind.Kvm => "kvm",
                _ => "unicorn",
            };

            Arguments.Add($"--backend={Backend}");

            if (Utils.SilentMode)
                Arguments.Add("--silent");

            if (MemoryBudget.Profile != MemoryProfile.Off)
                Arguments.Add($"--low-memory={MemoryBudget.Profile.ToString().ToLowerInvariant()}");

            if (Instance.Settings.NoHooks)
                Arguments.Add("--no-hooks");

            if (!Instance.Settings.Smp)
                Arguments.Add("--no-smp");
            else if (Instance.Settings.SmpWorkers > 0)
                Arguments.Add($"--cores={Instance.Settings.SmpWorkers}");

            if (!UnicornCodeCache.Enabled)
                Arguments.Add("--no-jit-cache");
            else if (!string.IsNullOrEmpty(UnicornCodeCache.CacheDirectory))
                Arguments.Add($"--jit-cache={UnicornCodeCache.CacheDirectory}");

            ForwardHostOptions(Arguments);

            Arguments.Add("-c");
            Arguments.Add("start;exit");
        }

        private static void ForwardHostOptions(System.Collections.ObjectModel.Collection<string> Arguments)
        {
            string[] HostArguments = Environment.GetCommandLineArgs();

            for (int i = 1; i < HostArguments.Length; i++)
            {
                string Argument = HostArguments[i];

                if (Argument.StartsWith("--net=", StringComparison.OrdinalIgnoreCase) ||
                    Argument.StartsWith("--net-allow=", StringComparison.OrdinalIgnoreCase) ||
                    Argument.Equals("-q", StringComparison.OrdinalIgnoreCase) ||
                    Argument.Equals("--quick", StringComparison.OrdinalIgnoreCase))
                {
                    Arguments.Add(Argument);
                    continue;
                }

                if ((Argument.Equals("--net", StringComparison.OrdinalIgnoreCase) ||
                     Argument.Equals("--net-allow", StringComparison.OrdinalIgnoreCase)) && i + 1 < HostArguments.Length)
                {
                    Arguments.Add(Argument);
                    Arguments.Add(HostArguments[++i]);
                }
            }
        }

        private static int GetSpawnDepth()
        {
            return int.TryParse(Environment.GetEnvironmentVariable(SpawnDepthVariable), out int Depth) && Depth > 0 ? Depth : 0;
        }

        /// <summary>
        /// Whether the creator asked for this process to hold its threads until it is resumed.
        /// </summary>
        internal static bool StartedSuspended()
        {
            return Environment.GetEnvironmentVariable(StartSuspendedVariable) == "1";
        }

        private static bool TryReserveLaunchSlot(out NTSTATUS Status)
        {
            int SessionProcesses = GuestSession.CountLive();
            if (SessionProcesses >= MaxSessionProcesses)
            {
                Utils.LogError($"[GuestProcessLauncher] Refusing to launch: the session already has {SessionProcesses} guest processes.");
                Status = NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;
                return false;
            }

            Status = NTSTATUS.STATUS_SUCCESS;
            return true;
        }

        private static bool IsAcceptableImagePath(string ImagePath)
        {
            string Path = StripNtPrefix(ImagePath).Replace('/', '\\');

            if (Path.StartsWith("\\\\", StringComparison.Ordinal))
                return false;

            if (Path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
                return false;

            return Path.Length >= 2 && Path[1] == ':' && char.IsAsciiLetter(Path[0]);
        }

        private static bool TryReadImageInformation(string HostImage, out SECTION_IMAGE_INFORMATION Information)
        {
            Information = default;

            try
            {
                using FileStream Stream = File.OpenRead(HostImage);

                Span<byte> Headers = stackalloc byte[HeaderBytes];
                int Available = Stream.ReadAtLeast(Headers, HeaderBytes, false);
                long FileSize = Stream.Length;

                if (Available < Unsafe.SizeOf<IMAGE_DOS_HEADER>())
                    return false;

                IMAGE_DOS_HEADER DosHeader = MemoryMarshal.Read<IMAGE_DOS_HEADER>(Headers);
                if (DosHeader.e_magic != DosSignature || DosHeader.e_lfanew < 0 ||
                    DosHeader.e_lfanew > Available - 4 - Unsafe.SizeOf<IMAGE_FILE_HEADER>() - 2)
                    return false;

                int FileHeaderOffset = DosHeader.e_lfanew + 4;
                int OptionalHeaderOffset = FileHeaderOffset + Unsafe.SizeOf<IMAGE_FILE_HEADER>();
                if (OptionalHeaderOffset + 2 > Available)
                    return false;

                if (BinaryPrimitives.ReadUInt32LittleEndian(Headers.Slice(DosHeader.e_lfanew, 4)) != NtSignature)
                    return false;

                IMAGE_FILE_HEADER FileHeader = MemoryMarshal.Read<IMAGE_FILE_HEADER>(Headers.Slice(FileHeaderOffset));
                ushort Magic = BinaryPrimitives.ReadUInt16LittleEndian(Headers.Slice(OptionalHeaderOffset, 2));

                if (Magic == OptionalHeaderMagic64)
                {
                    if (OptionalHeaderOffset + Unsafe.SizeOf<IMAGE_OPTIONAL_HEADER64>() > Available)
                        return false;

                    IMAGE_OPTIONAL_HEADER64 Optional = MemoryMarshal.Read<IMAGE_OPTIONAL_HEADER64>(Headers.Slice(OptionalHeaderOffset));

                    Information.TransferAddress = Optional.ImageBase + Optional.AddressOfEntryPoint;
                    Information.MaximumStackSize = Optional.SizeOfStackReserve;
                    Information.CommittedStackSize = Optional.SizeOfStackCommit;
                    Information.SubSystemType = Optional.Subsystem;
                    Information.SubSystemMinorVersion = Optional.MinorSubsystemVersion;
                    Information.SubSystemMajorVersion = Optional.MajorSubsystemVersion;
                    Information.MajorOperatingSystemVersion = Optional.MajorOperatingSystemVersion;
                    Information.MinorOperatingSystemVersion = Optional.MinorOperatingSystemVersion;
                    Information.DllCharacteristics = Optional.DllCharacteristics;
                    Information.LoaderFlags = Optional.LoaderFlags;
                    Information.CheckSum = Optional.CheckSum;
                }
                else if (Magic == OptionalHeaderMagic32)
                {
                    if (OptionalHeaderOffset + Unsafe.SizeOf<IMAGE_OPTIONAL_HEADER32>() > Available)
                        return false;

                    IMAGE_OPTIONAL_HEADER32 Optional = MemoryMarshal.Read<IMAGE_OPTIONAL_HEADER32>(Headers.Slice(OptionalHeaderOffset));

                    Information.TransferAddress = (ulong)Optional.ImageBase + Optional.AddressOfEntryPoint;
                    Information.MaximumStackSize = Optional.SizeOfStackReserve;
                    Information.CommittedStackSize = Optional.SizeOfStackCommit;
                    Information.SubSystemType = Optional.Subsystem;
                    Information.SubSystemMinorVersion = Optional.MinorSubsystemVersion;
                    Information.SubSystemMajorVersion = Optional.MajorSubsystemVersion;
                    Information.MajorOperatingSystemVersion = Optional.MajorOperatingSystemVersion;
                    Information.MinorOperatingSystemVersion = Optional.MinorOperatingSystemVersion;
                    Information.DllCharacteristics = Optional.DllCharacteristics;
                    Information.LoaderFlags = Optional.LoaderFlags;
                    Information.CheckSum = Optional.CheckSum;
                }
                else
                {
                    return false;
                }

                Information.ImageCharacteristics = FileHeader.Characteristics;
                Information.Machine = FileHeader.Machine;
                Information.ImageContainsCode = true;
                Information.ImageFileSize = (uint)Math.Min(FileSize, uint.MaxValue);
                return true;
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        private static string StripNtPrefix(string Path)
        {
            if (Path.StartsWith("\\??\\", StringComparison.Ordinal))
                return Path.Substring(4);

            if (Path.StartsWith("\\\\?\\", StringComparison.Ordinal))
                return Path.Substring(4);

            return Path;
        }

        private static string ReadUnicodeString(BinaryEmulator Instance, ulong Address, bool Is64)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, Is64 ? 16UL : 8UL))
                return null;

            ushort Length = Instance._emulator.ReadMemoryUShort(Address);
            ulong Buffer = Is64 ? Instance.ReadMemoryULong(Address + 8) : Instance.ReadMemoryUInt(Address + 4);
            if (Length == 0 || Length > MaxStringBytes || Buffer == 0 || !Instance.IsRegionMapped(Buffer, Length))
                return null;

            return Instance._emulator.ReadMemoryString(Buffer, Length, Encoding.Unicode)?.TrimEnd('\0');
        }

        private static string Encode(string Value)
        {
            return "base64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(Value));
        }

        private static string StripArgv0(string CommandLine)
        {
            if (string.IsNullOrWhiteSpace(CommandLine))
                return null;

            int Index = 0;
            if (CommandLine[0] == '"')
            {
                Index = CommandLine.IndexOf('"', 1);
                Index = Index < 0 ? CommandLine.Length : Index + 1;
            }
            else
            {
                while (Index < CommandLine.Length && CommandLine[Index] != ' ' && CommandLine[Index] != '\t')
                    Index++;
            }

            return Index >= CommandLine.Length ? null : CommandLine.Substring(Index).TrimStart(' ', '\t');
        }
    }
}
