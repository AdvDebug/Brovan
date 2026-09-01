using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // True only means the request was accepted. The process reports itself in the session table under SpawnToken.
    internal delegate bool GuestHostLauncher(string HostImage, string GuestArguments, string GuestDirectory, string SessionId, uint SpawnToken, int Depth);

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

        internal static bool TryLaunch(BinaryEmulator Instance, ulong ProcessParameters, string ImageNameHint, bool StartSuspended, out WinProcess Process, out SECTION_IMAGE_INFORMATION ImageInformation, out NTSTATUS Status)
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

            if (!WaitForStartup(HostProcess, SpawnToken, out uint ProcessId, out ulong PebAddress, out ulong StartupParameters))
            {
                Utils.LogError($"[GuestProcessLauncher] {Path.GetFileName(HostImage)} never reached guest startup.");
                Terminate(HostProcess);
                Status = NTSTATUS.STATUS_TIMEOUT;
                return false;
            }

            Process = new WinProcess
            {
                PID = ProcessId,
                PPID = Instance.WinHelper.PID,
                Name = Path.GetFileName(HostImage),
                Path = ImagePath,
                Arch = Instance._binary.Architecture,
                CreationTime = DateTime.UtcNow.ToFileTimeUtc(),
                Remote = RemoteGuestProcess.Adopt(ProcessId, HostProcess, Instance, PebAddress, StartupParameters),
            };

            Instance.TriggerEventMessage($"[GuestProcessLauncher] Launched {Process.Name} as guest process {Process.PID} (depth {Depth + 1}).", LogFlags.Syscall);

            Status = NTSTATUS.STATUS_SUCCESS;
            return true;
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
                CreateNoWindow = Utils.SilentMode,
            };

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
        private static bool WaitForStartup(Process HostProcess, uint SpawnToken, out uint ProcessId, out ulong PebAddress, out ulong StartupParameters)
        {
            long Deadline = Environment.TickCount64 + StartupTimeoutMilliseconds;

            while (true)
            {
                if (GuestSession.TryResolveSpawn(SpawnToken, out ProcessId, out _, out PebAddress, out StartupParameters))
                    return true;

                if ((HostProcess != null && HostProcess.HasExited) || Environment.TickCount64 >= Deadline)
                {
                    ProcessId = 0;
                    PebAddress = 0;
                    StartupParameters = 0;
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

            if (Instance.Settings.NoHooks)
                Arguments.Add("--no-hooks");

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
                if (DosHeader.e_magic != DosSignature || DosHeader.e_lfanew < 0)
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
