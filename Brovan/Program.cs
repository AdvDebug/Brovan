using static Brovan.Core.Helpers.Utils;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using Brovan.Core.Emulation;
using static Brovan.GeneralHelper;

namespace Brovan
{
    internal class Program
    {
        /// <summary>
        /// Determines whether to be a registry dump worker or not.
        /// </summary>
        /// <param name="args">args to resolve.</param>
        /// <returns>returns true if we are supposed to dump the registry. otherwise false.</returns>
        private static bool IsRegistryDumpWorker(string[] args)
        {
            if (!IsWindows)
                return false;

            foreach (string arg in args)
            {
                if (arg == "--dump-reg")
                    return true;
            }
            return false;
        }

        private static string GetRegistryDumpDirFromArgs(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--regdir" && i + 1 < args.Length)
                    return args[i + 1];
            }
            return "Reg";
        }

        public static bool DumpRegAsAdmin(string RegDir)
        {
            if (IsAdmin())
            {
                bool Ok = DumpReg(RegDir);
                if (Ok)
                    PrintHighlight("[*] Dumped registry hives successfully.");
                else
                    PrintHighlight("[-] Registry dump failed.");

                VerifyRegDump(RegDir, false);
                return Ok;
            }

            PrintHighlight("[*] Registry dump requires administrator privileges. Requesting UAC elevation...");

            string Args = $"--dump-reg --regdir \"{RegDir}\"";

            bool Started = RunAdminWait(Args, out int ExitCode);
            if (!Started)
            {
                PrintHighlight("[-] Elevation denied or failed.");
                return false;
            }

            if (ExitCode != 0)
                PrintHighlight($"[-] Elevated registry dump process returned ExitCode: {ExitCode}");
            else
                PrintHighlight("[*] Elevated registry dump process completed.");

            return VerifyRegDump(RegDir, false);
        }

        private static bool ArgsSpecifyKvmBackend(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg.StartsWith("--backend=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--backend=".Length).Trim().ToLowerInvariant();
                    return value == "kvm";
                }

                if (arg == "--backend" && i + 1 < args.Length)
                {
                    string value = (args[i + 1] ?? string.Empty).Trim().ToLowerInvariant();
                    return value == "kvm";
                }
            }
            return false;
        }

        private static bool HasSilentFlag(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string Arg = args[i];

                if (Arg == "-c" || Arg == "--command" || Arg == "--net" || Arg == "--net-allow")
                {
                    i++;
                    continue;
                }

                if (Arg == "-s" || Arg == "--silent")
                    return true;

                if (!Arg.StartsWith("-", StringComparison.Ordinal))
                    return false;
            }

            return false;
        }

        static void ShowHelp()
        {
            Console.WriteLine("Brovan - User-mode binary emulator");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  Brovan [options] <path-to-binary> [program arguments...]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -q, --quick       Run in quick mode (recommended for large binaries and smaller memory usage, always on for this build)");
            Console.WriteLine("  -h, --help        Show this help");
            Console.WriteLine("  -s, --silent      Run the emulator in silent mode, which only shows std output coming from the emulated program.");
            Console.WriteLine("  -c, --command     Execute commands directly, seperated by ';'.");
            Console.WriteLine("  --net=<mode>      Set host networking policy: none, loopback (default), full");
            Console.WriteLine("  --net-allow=<ip>  Allow a specific IPv4 or IPv6 address in addition to the selected policy.");
            Console.WriteLine("  --no-hooks        Run the emulator with no hooks. useful when you want maximum performance and want to see some program output.");
            Console.WriteLine("  --backend=<name>  Choose the emulation backend: unicorn (default) or kvm.");
            Console.WriteLine();
            Console.WriteLine("Notes:");
            Console.WriteLine("  All Brovan flags must be passed before the program path.");
            Console.WriteLine("  Everything after the program path is passed to the emulated program as-is as arguments.");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  Brovan sample.exe");
            Console.WriteLine("  Brovan --quick sample.exe");
            Console.WriteLine("  Brovan --quick -c \"debug;start\" sample.exe");
            Console.WriteLine("  Brovan sample.exe --help");
        }

        private static string BuildRawProgramArguments(string[] ProgramArguments)
        {
            if (ProgramArguments.Length == 0)
                return null;

            StringBuilder Builder = new StringBuilder();
            for (int i = 0; i < ProgramArguments.Length; i++)
            {
                if (i != 0)
                    Builder.Append(' ');

                Builder.Append(GeneralHelper.QuoteCommandLineArg(ProgramArguments[i]));
            }

            return Builder.ToString();
        }

        private static bool TryParseNetworkMode(string Value, out NetworkAccessMode Mode)
        {
            switch ((Value ?? string.Empty).Trim().ToLowerInvariant())
            {
                case "full":
                    Mode = NetworkAccessMode.Full;
                    return true;
                case "none":
                    Mode = NetworkAccessMode.None;
                    return true;
                case "loopback":
                    Mode = NetworkAccessMode.Loopback;
                    return true;
                default:
                    Mode = NetworkAccessMode.None;
                    return false;
            }
        }

        private static bool TryAddAllowedNetworkAddress(NetworkAccessPolicy Policy, string Value)
        {
            if (!IPAddress.TryParse(Value, out IPAddress? Address))
                return false;

            Policy.AddAllowedAddress(Address);
            return true;
        }

        private static bool TryParseBackendKind(string Value, out EmulationBackendKind Kind)
        {
            switch ((Value ?? string.Empty).Trim().ToLowerInvariant())
            {
                case "unicorn":
                case "":
                    Kind = EmulationBackendKind.Unicorn;
                    return true;
                case "kvm":
                    Kind = EmulationBackendKind.Kvm;
                    return true;
                default:
                    Kind = EmulationBackendKind.Unicorn;
                    return false;
            }
        }

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            /*if (!IsWindows)
            {
                PrintHighlight("[-] Brovan currently supports Windows only. Cross-platform support are not fully supported at the moment.", true);
                Environment.Exit(-1);
            }*/

            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            SilentMode = HasSilentFlag(args);

            bool KvmBackendRequested = ArgsSpecifyKvmBackend(args);

            if (!IsWindows && !Directory.Exists(WindowsLibsPath))
            {
                PrintHighlight($"[-] Couldn't find the windows libs directory inside. expected path: {WindowsLibsPath}", true);
                Environment.Exit(0);
            }

            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                Exception ex = (Exception)e.ExceptionObject;
                LogError($"[Global Unhandled Exception]: {ex.Message}\nStack Trace:\n\n{ex.StackTrace}");
            };

            // Add a handler specifically for linux since .NET doesn't seem to show any stack traces on linux
            if (IsLinux)
            {
                LinuxNativeCrashHandler.Install((sig, fault, rip, modulepath, modulebase, symbolname, symboladdr, siCode, trapNo, err) =>
                {
                    LogError($"[Native Unhandled Linux Exception]: Signal={(sig == 11 ? LinuxSignal.SIGSEGV : LinuxSignal.None)}({sig}), Reason={(sig == 11 ? LinuxNativeCrashHandler.GetSegvReason(siCode) : "N/A")}, Access={(sig == 11 ? LinuxNativeCrashHandler.GetPageFaultAccess(trapNo, err) : "N/A")}, Fault=0x{fault:X}, RIP=0x{rip:X}, Module={(modulepath != IntPtr.Zero ? Marshal.PtrToStringUTF8(modulepath) : "unknown")}, Base=0x{modulebase:X}, ModuleOff=0x{(modulebase != 0 && rip >= modulebase ? rip - modulebase : 0):X}, Symbol={(symbolname != IntPtr.Zero ? Marshal.PtrToStringUTF8(symbolname) : "unknown")}, SymbolOff=0x{(symboladdr != 0 && rip >= symboladdr ? rip - symboladdr : 0):X}");
                    PrintHighlight("[-] Unhandled Native Exception has occured. More information can be found in the logs file.", true);
                }, LinuxSignal.FatalException);
            }

            PrepareConsole();

            if (IsRegistryDumpWorker(args))
            {
                string RegDir = GetRegistryDumpDirFromArgs(args);
                bool Ok = DumpReg(RegDir);
                Environment.Exit(Ok ? 0 : 1);
                return;
            }

            if (!File.Exists(BinaryEmulator.ApiSetMapPath))
            {
                if (IsWindows)
                {
                    try
                    {
                        if (DumpApiSetMap())
                        {
                            PrintHighlight("[*] Dumped ApiSetMap of the host to the emulator's directory to be used.");
                        }
                    }
                    catch (Exception ex)
                    {
                        PrintHighlight($"[-] Failed to dump ApiSetMap: \"{ex.Message}\". Brovan will attempt to generate one.");
                        try
                        {
                            byte[] ApiSetMap = CrossGenerator.GenerateMap();
                            File.WriteAllBytes(Path.Combine(AppContext.BaseDirectory, "apisetmap.bin"), ApiSetMap);
                            PrintHighlight("[+] Custom ApiSetMap was generated.", true);
                        }
                        catch (Exception exception)
                        {
                            PrintHighlight($"[-] Failed to generate and write the map: {exception.Message}", true);
                            Environment.Exit(-1);
                        }
                    }
                }
                else
                {
                    PrintHighlight("[!] Cannot dump ApiSetMap because you are not running on Windows. The emulator will try to make a custom one.", true);
                    try
                    {
                        byte[] ApiSetMap = CrossGenerator.GenerateMap();
                        File.WriteAllBytes(Path.Combine(AppContext.BaseDirectory, "apisetmap.bin"), ApiSetMap);
                        PrintHighlight("[+] Custom ApiSetMap was generated.", true);
                    }
                    catch (Exception ex)
                    {
                        PrintHighlight($"[-] Failed to generate and write the map: {ex.Message}", true);
                        Environment.Exit(-1);
                    }
                }
            }

            string RegPath = Path.Combine(AppContext.BaseDirectory, "WinReg");
            if (!Directory.Exists(RegPath))
            {
                if (IsWindows)
                {
                    DumpRegAsAdmin("WinReg");
                }
                else
                {
                    PrintHighlight("[-] Cannot dump Registry because you are not running on Windows. Please dump a windows registry to the emulator's current path with the directory name 'WinReg' from another machine and try again.", true);
                    Environment.Exit(-1);
                }
            }
            else if (!VerifyRegDump(RegPath, true))
            {
                if (IsWindows)
                {
                    DumpRegAsAdmin("WinReg");
                }
                else
                {
                    PrintHighlight("[-] Some registry hives are missing. dump them from a windows machine.");
                }
            }

            bool Quick = true;
            bool NoHooks = false;
            bool Silent = false;
            string Command = null;
            string FilePath = null;
            EmulationBackendKind BackendKind = EmulationBackendKind.Unicorn;
            NetworkAccessPolicy NetworkPolicy = new NetworkAccessPolicy(NetworkAccessMode.Loopback);
            List<string> ProgramArgumentsList = new List<string>();

            for (int i = 0; i < args.Length; i++)
            {
                string Arg = args[i];

                if (FilePath != null)
                {
                    ProgramArgumentsList.Add(Arg);
                    continue;
                }

                switch (Arg)
                {
                    case "help":
                    case "-h":
                    case "-help":
                    case "--help":
                        ShowHelp();
                        return;
                    case "-q":
                    case "--quick":
                        Quick = true;
                        continue;
                    case "-s":
                    case "--silent":
                        Silent = true;
                        continue;
                    case "-c":
                    case "--command":
                        if (i + 1 >= args.Length)
                            continue;

                        Command = args[i + 1];
                        i++;
                        continue;
                    case "--net":
                        if (i + 1 >= args.Length || !TryParseNetworkMode(args[i + 1], out NetworkAccessMode ArgumentNetworkMode))
                        {
                            PrintHighlight("[-] Invalid network mode. expected: full, none, loopback.", true);
                            return;
                        }

                        NetworkPolicy.Mode = ArgumentNetworkMode;
                        i++;
                        continue;
                    case "--net-allow":
                        if (i + 1 >= args.Length || !TryAddAllowedNetworkAddress(NetworkPolicy, args[i + 1]))
                        {
                            PrintHighlight("[-] Invalid network allow address. expected an IPv4 or IPv6 address.", true);
                            return;
                        }

                        i++;
                        continue;
                    case "--no-hooks":
                        NoHooks = true;
                        continue;
                    case "--backend":
                        if (i + 1 >= args.Length || !TryParseBackendKind(args[i + 1], out EmulationBackendKind ArgumentBackendKind))
                        {
                            PrintHighlight("[-] Invalid backend. expected: unicorn, kvm.", true);
                            return;
                        }

                        BackendKind = ArgumentBackendKind;
                        i++;
                        continue;
                }

                if (IsWindows && BackendKind == EmulationBackendKind.Unicorn && Unicorn.IsCFGEnabled())
                {
                    if (Environment.GetEnvironmentVariable("BROVAN_CFG_DISABLED") != "1")
                    {
                        PrintHighlight("[!] Control Flow Guard is enabled, Brovan will try to restart the process with CFG disabled.", true);
                        if (!RestartProcessWithCfgDisabled(true))
                        {
                            PrintHighlight("[-] Unicorn doesn't support CFG Mitigation which is currently enabled in the process. Failed to restart with CFG disabled. Please use a build without CFG or clear the GuardCF flag in the PE header.", true);
                            Environment.Exit(-1);
                        }
                    }
                    else
                    {
                        PrintHighlight("[-] Unicorn doesn't support CFG Mitigation which is currently enabled in the process, and Brovan failed to restart with CFG disabled. Please use a build without CFG or clear the GuardCF flag in the PE header.", true);
                        Environment.Exit(-1);
                    }

                    Environment.Exit(0); // it should exit by itself inside RestartProcessWithCfgDisabled but keep this here too just in case
                }

                if (Arg.StartsWith("--net=", StringComparison.OrdinalIgnoreCase))
                {
                    string Value = Arg.Substring("--net=".Length);
                    if (!TryParseNetworkMode(Value, out NetworkAccessMode InlineNetworkMode))
                    {
                        PrintHighlight("[-] Invalid network mode. expected: full, none, loopback.", true);
                        return;
                    }

                    NetworkPolicy.Mode = InlineNetworkMode;
                    continue;
                }

                if (Arg.StartsWith("--net-allow=", StringComparison.OrdinalIgnoreCase))
                {
                    string Value = Arg.Substring("--net-allow=".Length);
                    if (!TryAddAllowedNetworkAddress(NetworkPolicy, Value))
                    {
                        PrintHighlight("[-] Invalid network allow address. expected an IPv4 or IPv6 address.", true);
                        return;
                    }

                    continue;
                }

                if (Arg.StartsWith("--backend=", StringComparison.OrdinalIgnoreCase))
                {
                    string Value = Arg.Substring("--backend=".Length);
                    if (!TryParseBackendKind(Value, out EmulationBackendKind InlineBackendKind))
                    {
                        PrintHighlight("[-] Invalid backend. expected: unicorn, kvm.", true);
                        return;
                    }

                    BackendKind = InlineBackendKind;
                    continue;
                }

                if (Arg.StartsWith("-", StringComparison.Ordinal))
                    continue;

                FilePath = Arg;
            }

            if (string.IsNullOrWhiteSpace(FilePath))
            {
                ShowHelp();
                return;
            }

            if (!File.Exists(FilePath))
            {
                PrintHighlight($"[-] File with the path \"{FilePath}\" does not exist.");
                return;
            }

            string[] ProgramArguments = ProgramArgumentsList.ToArray();
            string RawProgramArguments = BuildRawProgramArguments(ProgramArguments);

            // Set the dll import resolver based on the platform
            NativeLibraryResolver.Register();
            EmulationMenu.EmulationMenu.RunEmulator(FilePath, Quick, Silent, Command, RawProgramArguments, ProgramArguments, NetworkPolicy, NoHooks, BackendKind);
        }
    }
}