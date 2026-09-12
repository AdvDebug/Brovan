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
        public bool HypervisorAvailable;
        public string HypervisorName = string.Empty;
        public string HypervisorHint = string.Empty;
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
                string Sibling = Path.GetFullPath(Path.Combine(Base, "..", "..", "..", "..", "Brovan", "bin", Configuration, "net8.0", ExecutableName));
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

            if (OperatingSystem.IsWindows())
            {
                State.HypervisorName = "Windows Hypervisor Platform";
                State.HypervisorAvailable = HypervisorPresent();
                State.HypervisorHint = "Turn it on under Windows Features, as \"Windows Hypervisor Platform\", then restart.";
            }
            else
            {
                State.HypervisorName = "KVM";
                State.HypervisorAvailable = KvmUsable();
                State.HypervisorHint = "Needs /dev/kvm, which the kvm_intel or kvm_amd module provides, and read and write access to it.";
            }

            return State;
        }

        // WinHvPlatform.dll ships whether or not WHP is turned on, so the capability must be asked for.
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static bool HypervisorPresent()
        {
            try
            {
                int Status = WHvGetCapability(WhvCapabilityHypervisorPresent, out int Present, sizeof(int), out uint Written);
                return Status >= 0 && Written >= sizeof(int) && Present != 0;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private const uint WhvCapabilityHypervisorPresent = 0;

        [DllImport("WinHvPlatform.dll")]
        private static extern int WHvGetCapability(uint Code, out int Buffer, uint BufferSize, out uint Written);

        // Presence is not access. The backend opens it read-write.
        private static bool KvmUsable()
        {
            try
            {
                using SafeFileHandle Device = File.OpenHandle("/dev/kvm", FileMode.Open, FileAccess.ReadWrite);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static string BackendValue => OperatingSystem.IsWindows() ? "whp" : "kvm";

        public static List<string> LaunchArguments(Profile Program, IReadOnlyDictionary<string, string> Defaults, IReadOnlyList<SettingEntry> Schema)
        {
            List<string> Arguments = new List<string>();

            foreach (SettingEntry Entry in Schema)
            {
                if (!Entry.AppliesToHost)
                    continue;

                if (!Program.Settings.TryGetValue(Entry.Key, out string? Value) && !Defaults.TryGetValue(Entry.Key, out Value))
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
