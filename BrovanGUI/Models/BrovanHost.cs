using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BrovanGUI.Models
{
    public sealed class SetupState
    {
        public string? Executable;
        public string? Directory;
        public bool SystemFiles;
        public bool Runtimes;
        public bool Registry;
        public string? DxvkVersion;
        public bool HostIsWindows = OperatingSystem.IsWindows();
    }

    public static class BrovanHost
    {
        private static readonly TimeSpan Drain = TimeSpan.FromSeconds(2);

        public static string ExecutableName => OperatingSystem.IsWindows() ? "Brovan.exe" : "Brovan";

        public static string? Locate(string Configured)
        {
            if (Configured.Length != 0 && File.Exists(Configured))
                return Path.GetFullPath(Configured);

            string Base = AppContext.BaseDirectory;
            string Beside = Path.Combine(Base, ExecutableName);
            if (File.Exists(Beside))
                return Beside;

            foreach (string Configuration in new[] { "Release", "Debug" })
            {
                string Sibling = Path.GetFullPath(Path.Combine(Base, "..", "..", "..", "..", "Brovan", "bin", Configuration, "net10.0", ExecutableName));
                if (File.Exists(Sibling))
                    return Sibling;
            }

            return null;
        }

        public static SetupState Inspect(string? Executable)
        {
            SetupState State = new SetupState { Executable = Executable };
            if (Executable != null)
            {
                string Directory = Path.GetDirectoryName(Executable) ?? string.Empty;
                State.Directory = Directory;
                State.SystemFiles = File.Exists(Path.Combine(Directory, "WindowsLibs", "ntdll.dll"));
                State.Runtimes = File.Exists(Path.Combine(Directory, "WindowsLibs", "msvcp140.dll"));
                State.Registry = File.Exists(Path.Combine(Directory, "WinReg", "SYSTEM"))
                    && File.Exists(Path.Combine(Directory, "WinReg", "SOFTWARE"));

                string VersionFile = Path.Combine(Directory, "dxvk.version");
                if (File.Exists(VersionFile))
                {
                    try
                    {
                        State.DxvkVersion = File.ReadAllText(VersionFile).Trim();
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            return State;
        }

        public static string HypervisorName => OperatingSystem.IsWindows() ? "Windows Hypervisor Platform" : "KVM";

        public static string? HypervisorProblem()
        {
            if (RuntimeInformation.OSArchitecture != Architecture.X64)
                return "It runs x86 programs only on an x86-64 processor, and this computer has an " + RuntimeInformation.OSArchitecture + " processor.";

            return OperatingSystem.IsWindows() ? WhpProblem() : KvmProblem();
        }

        // WinHvPlatform.dll ships whether or not WHP is turned on, so the capability must be asked for.
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static string? WhpProblem()
        {
            int Status;
            int Present;
            uint Written;
            try
            {
                Status = WHvGetCapability(WhvCapabilityHypervisorPresent, out Present, sizeof(int), out Written);
            }
            catch (Exception Error) when (Error is DllNotFoundException or EntryPointNotFoundException)
            {
                return "Windows Hypervisor Platform is not installed. Turn it on under Windows Features, then restart.";
            }

            // PF_VIRT_FIRMWARE_ENABLED reads false while a hypervisor is running, so it is checked only when none is.
            if (Status < 0 || Written < sizeof(int) || Present == 0)
            {
                return IsProcessorFeaturePresent(PfVirtFirmwareEnabled)
                    ? "Windows Hypervisor Platform is turned off. Turn it on under Windows Features, then restart."
                    : "Virtualization is turned off in the firmware. Turn on Intel VT-x or AMD-V in the BIOS or UEFI settings.";
            }

            Status = WHvCreatePartition(out IntPtr Partition);
            if (Status < 0)
                return "Windows Hypervisor Platform could not create a virtual machine (error 0x" + Status.ToString("X8") + "). Check that it is turned on under Windows Features.";

            WHvDeletePartition(Partition);
            return null;
        }

        private const uint WhvCapabilityHypervisorPresent = 0;
        private const uint PfVirtFirmwareEnabled = 21;

        [DllImport("WinHvPlatform.dll")]
        private static extern int WHvGetCapability(uint Code, out int Buffer, uint BufferSize, out uint Written);

        [DllImport("WinHvPlatform.dll")]
        private static extern int WHvCreatePartition(out IntPtr Partition);

        [DllImport("WinHvPlatform.dll")]
        private static extern int WHvDeletePartition(IntPtr Partition);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsProcessorFeaturePresent(uint Feature);

        private static string? KvmProblem()
        {
            try
            {
                using SafeFileHandle Device = File.OpenHandle("/dev/kvm", FileMode.Open, FileAccess.ReadWrite);
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return "KVM is on, but this user may not open /dev/kvm. Run \"sudo usermod -aG kvm $USER\", then log out and in again.";
            }
            catch (Exception)
            {
                return "There is no /dev/kvm, which the kvm_intel or kvm_amd module provides. Turn virtualization on in the firmware if the module will not load.";
            }
        }

        public const string BackendKey = "backend.kind";

        public static string BackendValue => OperatingSystem.IsWindows() ? "whp" : "kvm";

        private const ushort MzMagic = 0x5A4D;
        private const uint ElfMagic = 0x464C457F;

        public static bool IsProgram(string Path)
        {
            uint Magic = ReadMagic(Path);
            return (ushort)Magic == MzMagic || Magic == ElfMagic;
        }

        public static bool IsLinuxProgram(string Path)
        {
            return ReadMagic(Path) == ElfMagic;
        }

        private static uint ReadMagic(string Path)
        {
            Span<byte> Header = stackalloc byte[4];
            try
            {
                using SafeFileHandle Handle = File.OpenHandle(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return RandomAccess.Read(Handle, Header, 0) == Header.Length ? BinaryPrimitives.ReadUInt32LittleEndian(Header) : 0;
            }
            catch (IOException)
            {
                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                return 0;
            }
        }

        // Brovan's own defaults suit analysis, not launching.
        public static string? LauncherDefault(string Key, bool HypervisorAvailable)
        {
            return Key switch
            {
                "log.silent" => "true",
                "backend.hooks" => "false",
                BackendKey => HypervisorAvailable ? BackendValue : "unicorn",
                _ => null,
            };
        }

        public static string? ChosenValue(Profile? Program, IReadOnlyDictionary<string, string> Defaults, string Key)
        {
            if (Program != null && Program.Settings.TryGetValue(Key, out string? Value))
                return Value;

            return Defaults.TryGetValue(Key, out Value) ? Value : null;
        }

        public static List<string> LaunchArguments(Profile Program, IReadOnlyDictionary<string, string> Defaults, IReadOnlyList<SettingEntry> Schema, bool HypervisorAvailable)
        {
            List<string> Arguments = new List<string>();

            foreach (SettingEntry Entry in Schema)
            {
                if (!Entry.AppliesToHost)
                    continue;

                string? Value = ChosenValue(Program, Defaults, Entry.Key) ?? LauncherDefault(Entry.Key, HypervisorAvailable);
                if (Value == null)
                    continue;

                if (Entry.Repeatable)
                {
                    foreach (string Item in Value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        Arguments.Add("--set=" + Entry.Key + "=" + Item);
                }
                else
                {
                    Arguments.Add("--set=" + Entry.Key + "=" + Value);
                }
            }

            if (Program.WorkingDirectory.Length != 0)
            {
                Arguments.Add("--cwd");
                Arguments.Add(Program.WorkingDirectory);
            }

            // The interactive prompt would otherwise wait on a pipe that never speaks.
            Arguments.Add("-c");
            Arguments.Add("start;exit");

            if (Program.Arguments.Trim().Length != 0)
            {
                Arguments.Add("--guest-cmdline");
                Arguments.Add("base64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(Program.Arguments.Trim())));
            }

            Arguments.Add(Program.Executable);
            return Arguments;
        }

        // OnOutput gets the bytes as they arrive, partial lines included.
        public static Process Start(string Executable, IReadOnlyList<string> Arguments, Action<string> OnOutput, Action<int> OnExit)
        {
            ProcessStartInfo Info = new ProcessStartInfo(Executable)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(Executable),
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            foreach (string Argument in Arguments)
                Info.ArgumentList.Add(Argument);

            Process Child = new Process { StartInfo = Info, EnableRaisingEvents = true };
            Child.Start();
            LeaveEfficiencyMode(Child);

            // A pipe read wakes once per write the child makes. A thread of its own keeps that off the pool.
            Task Output = Task.Factory.StartNew(() => Pump(Child.StandardOutput.BaseStream, OnOutput), TaskCreationOptions.LongRunning);
            Task Errors = Task.Factory.StartNew(() => Pump(Child.StandardError.BaseStream, OnOutput), TaskCreationOptions.LongRunning);
            _ = Task.Run(async () =>
            {
                await Child.WaitForExitAsync();

                // A grandchild that inherited the pipe holds its write end open, so the pumps can miss end of file.
                await Task.WhenAny(Task.WhenAll(Output, Errors), Task.Delay(Drain));
                OnExit(Child.ExitCode);
            });

            return Child;
        }

        private static void Pump(Stream Source, Action<string> OnOutput)
        {
            byte[] Buffer = new byte[16384];
            char[] Chars = new char[Encoding.UTF8.GetMaxCharCount(Buffer.Length)];
            Decoder Decoder = Encoding.UTF8.GetDecoder();

            try
            {
                while (true)
                {
                    int Read = Source.Read(Buffer, 0, Buffer.Length);
                    if (Read <= 0)
                        break;

                    int Count = Decoder.GetChars(Buffer, 0, Read, Chars, 0);
                    if (Count != 0)
                        OnOutput(new string(Chars, 0, Count));
                }
            }
            catch (Exception)
            {
            }
        }

        public static bool SendLine(Process Child, string Line)
        {
            try
            {
                if (Child.HasExited)
                    return false;

                Child.StandardInput.WriteLine(Line);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static string CommandLine(string Executable, IReadOnlyList<string> Arguments)
        {
            StringBuilder Builder = new StringBuilder();
            Builder.Append(Quote(Path.GetFileName(Executable)));
            foreach (string Argument in Arguments)
                Builder.Append(' ').Append(Quote(Argument));

            return Builder.ToString();
        }

        private static readonly char[] QuoteTriggers = { ' ', '\t', '"', ';' };

        // CommandLineToArgvW: a backslash run doubles before a quote and at the end of the argument.
        private static string Quote(string Argument)
        {
            if (Argument.Length != 0 && Argument.IndexOfAny(QuoteTriggers) < 0)
                return Argument;

            StringBuilder Builder = new StringBuilder();
            Builder.Append('"');

            int Backslashes = 0;
            foreach (char Character in Argument)
            {
                if (Character == '\\')
                {
                    Backslashes++;
                    continue;
                }

                if (Character == '"')
                {
                    Builder.Append('\\', Backslashes * 2 + 1).Append('"');
                    Backslashes = 0;
                    continue;
                }

                if (Backslashes != 0)
                {
                    Builder.Append('\\', Backslashes);
                    Backslashes = 0;
                }

                Builder.Append(Character);
            }

            Builder.Append('\\', Backslashes * 2).Append('"');
            return Builder.ToString();
        }

        // EcoQoS and the priority class are both inherited, so the emulator is put back to the defaults
        // after it starts. Linux has no equivalent an unprivileged process can undo for its children.
        public static void EnterEfficiencyMode()
        {
            if (!OperatingSystem.IsWindows())
                return;

            try
            {
                using Process Self = Process.GetCurrentProcess();
                Self.PriorityClass = ProcessPriorityClass.BelowNormal;
                SetPowerThrottling(Self.Handle, PowerThrottlingExecutionSpeed, PowerThrottlingExecutionSpeed);
            }
            catch (Exception)
            {
            }
        }

        private static void LeaveEfficiencyMode(Process Child)
        {
            if (!OperatingSystem.IsWindows())
                return;

            try
            {
                Child.PriorityClass = ProcessPriorityClass.Normal;
                SetPowerThrottling(Child.Handle, 0, 0);
            }
            catch (Exception)
            {
            }
        }

        private const int ProcessPowerThrottling = 4;
        private const uint PowerThrottlingCurrentVersion = 1;
        private const uint PowerThrottlingExecutionSpeed = 1;

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessPowerThrottlingState
        {
            public uint Version;
            public uint ControlMask;
            public uint StateMask;
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static void SetPowerThrottling(IntPtr Handle, uint ControlMask, uint StateMask)
        {
            ProcessPowerThrottlingState State = new ProcessPowerThrottlingState
            {
                Version = PowerThrottlingCurrentVersion,
                ControlMask = ControlMask,
                StateMask = StateMask,
            };

            SetProcessInformation(Handle, ProcessPowerThrottling, ref State, (uint)Marshal.SizeOf<ProcessPowerThrottlingState>());
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessInformation(IntPtr Process, int InformationClass, ref ProcessPowerThrottlingState Information, uint Size);

        public static void OpenExternal(string Target)
        {
            try
            {
                Process.Start(new ProcessStartInfo(Target) { UseShellExecute = true });
            }
            catch (Exception)
            {
            }
        }
    }
}
