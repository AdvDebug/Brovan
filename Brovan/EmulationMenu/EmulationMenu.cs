using System.Text;
using Brovan.Core;
using static Brovan.Core.Helpers.Utils;
using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Analysis;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Emulation.OS.Windows;
using System.Runtime.InteropServices;
using System.Reflection;
using static Brovan.Variables;
using static Brovan.Helpers;
using static Brovan.Handlers;
using System.Diagnostics.CodeAnalysis;
using Brovan.Core.Emulation.OS;

namespace Brovan.EmulationMenu
{
    internal class EmulationMenu
    {
        private enum CommandHelpType
        {
            Core,
            Debug,
            Memory,
            Analysis,
            Network,
        }

        private sealed class CommandHelpEntry
        {
            public CommandHelpEntry(CommandHelpType type, string name, string usage, string description, params string[] aliases)
            {
                Type = type;
                Name = name;
                Usage = usage;
                Description = description;
                Aliases = aliases ?? Array.Empty<string>();
            }

            public CommandHelpType Type { get; }
            public string Name { get; }
            public string Usage { get; }
            public string Description { get; }
            public string[] Aliases { get; }
        }

        private static readonly CommandHelpEntry[] CommandHelpEntries =
        {
            new CommandHelpEntry(CommandHelpType.Core, "help", "help [command]", "Show available commands or details for one command.", "?", "commands"),
            new CommandHelpEntry(CommandHelpType.Core, "start", "start", "Initialize the emulator instance."),
            new CommandHelpEntry(CommandHelpType.Core, "run", "run", "Run the current thread using the scheduler."),
            new CommandHelpEntry(CommandHelpType.Core, "continue", "continue", "Resume emulation from the current instruction pointer.", "c", "cont"),
            new CommandHelpEntry(CommandHelpType.Core, "clear", "clear", "Clear the console output.", "cls"),
            new CommandHelpEntry(CommandHelpType.Core, "exit", "exit", "Exit the emulator.", "quit"),
            new CommandHelpEntry(CommandHelpType.Debug, "showinstrs", "showinstrs [module_name|start-end]", "Enable instruction tracing (optionally filter)."),
            new CommandHelpEntry(CommandHelpType.Debug, "step", "step", "Execute a single instruction."),
            new CommandHelpEntry(CommandHelpType.Debug, "stepover", "stepover", "Step over a call instruction."),
            new CommandHelpEntry(CommandHelpType.Debug, "debug", "debug", "Toggle debug mode."),
            new CommandHelpEntry(CommandHelpType.Debug, "hideinstrs", "hideinstrs", "Disable instruction tracing."),
            new CommandHelpEntry(CommandHelpType.Debug, "bp", "bp <add|del|list|clear>", "Manage breakpoints (supports conditional).", "break"),
            new CommandHelpEntry(CommandHelpType.Debug, "watch", "watch <add|del|list|clear>", "Manage read/write/fetch watchpoints.", "wp"),
            new CommandHelpEntry(CommandHelpType.Debug, "threads", "threads <list|info|switch|suspend|resume|kill|priority|rename|regs>", "Inspect and control emulated threads.", "thread", "t"),
            new CommandHelpEntry(CommandHelpType.Debug, "handles", "handles <list|info|refs|inspect|close|flags|access|target|dup|set|setraw>", "Inspect and edit Windows handles or Linux file descriptors.", "handle", "fds", "fd"),
            new CommandHelpEntry(CommandHelpType.Debug, "snap", "snap", "Take an emulator snapshot."),
            new CommandHelpEntry(CommandHelpType.Debug, "restore", "restore", "Restore the last snapshot."),
            new CommandHelpEntry(CommandHelpType.Debug, "set", "set <register> <value>", "Set a register value."),
            new CommandHelpEntry(CommandHelpType.Debug, "get", "get <register>", "Read a register value."),
            new CommandHelpEntry(CommandHelpType.Debug, "dumpregs", "dumpregs", "Print register state."),
            new CommandHelpEntry(CommandHelpType.Memory, "dumpconsole", "dumpconsole", "Dump the current console output."),
            new CommandHelpEntry(CommandHelpType.Memory, "hexdump", "hexdump <address> <size>", "Dump memory as hex and ASCII."),
            new CommandHelpEntry(CommandHelpType.Memory, "disasm", "disasm <address> <size>", "Disassemble memory at the given address."),
            new CommandHelpEntry(CommandHelpType.Memory, "memwrite", "memwrite <addr> <hex-bytes|file_path>", "Write bytes or assembled instruction bytes."),
            new CommandHelpEntry(CommandHelpType.Memory, "gpatch", "gpatch <addr> <hex-bytes|file_path>", "Apply a ghost patch. modifies bytes in memory but upon reading it by the program it reads the original bytes."),
            new CommandHelpEntry(CommandHelpType.Memory, "parse_struct", "parse_struct <address> <struct_name>", "Parse and display a Windows structure."),
            new CommandHelpEntry(CommandHelpType.Memory, "write_struct", "write_struct [address] <struct_name> <field=value&...>", "Write a Windows structure to memory."),
            new CommandHelpEntry(CommandHelpType.Memory, "regions", "regions", "List mapped memory regions."),
            new CommandHelpEntry(CommandHelpType.Memory, "map", "map <address> <size>", "Map memory at an address (use 0 for auto)."),
            new CommandHelpEntry(CommandHelpType.Memory, "checkprot", "checkprot <address>", "Show memory protection for an address."),
            new CommandHelpEntry(CommandHelpType.Memory, "findstr", "findstr <text> [ascii|utf16] [max-results]", "Find ASCII/UTF-16 strings in mapped memory."),
            new CommandHelpEntry(CommandHelpType.Analysis, "modules", "modules", "List loaded modules."),
            new CommandHelpEntry(CommandHelpType.Analysis, "bininfo", "bininfo [summary|functions|exports|imports|sections|dotnet]", "Show parsed binary metadata (disabled in quick mode).", "binaryinfo"),
            new CommandHelpEntry(CommandHelpType.Analysis, "syscall", "syscall <list|last|failed|tid|name|contains|export|clear|trace|rule|rules>", "Inspect syscall history while trace is enabled and manage syscall behavior/rules.", "syscalls"),
            new CommandHelpEntry(CommandHelpType.Analysis, "calltrace", "calltrace <on|off|clear|list|depth>", "Trace call/ret instructions and maintain a lightweight call stack.", "ct"),
            new CommandHelpEntry(CommandHelpType.Analysis, "callstack", "callstack [thread_id] [max_frames]", "Show the traced call stack for a thread.", "bt"),
            new CommandHelpEntry(CommandHelpType.Analysis, "funcmon", "funcmon <address|symbol> [cc] [arg_types...]", "Monitor function enter/leave with parameters."),
            new CommandHelpEntry(CommandHelpType.Analysis, "ldrplog", "ldrplog <address>|off|once", "Decode internal ntdll loader log calls."),
            new CommandHelpEntry(CommandHelpType.Network, "pcap", "pcap <on|off|status> [path]", "Dump emulated network traffic to a pcap file.", "netdump", "capture")
        };

        private static readonly Dictionary<string, CommandHelpEntry> CommandHelpLookup = BuildCommandHelpLookup();
        private static bool CancelKeyPressRegistered;
        private static volatile bool Exiting;

        private static Dictionary<string, CommandHelpEntry> BuildCommandHelpLookup()
        {
            Dictionary<string, CommandHelpEntry> lookup = new(StringComparer.OrdinalIgnoreCase);

            foreach (CommandHelpEntry entry in CommandHelpEntries)
            {
                lookup[entry.Name] = entry;
                foreach (string alias in entry.Aliases)
                    lookup[alias] = entry;
            }

            return lookup;
        }

        private static void ShowHelp(string[] args)
        {
            if (args.Length > 0 && CommandHelpLookup.TryGetValue(args[0], out CommandHelpEntry entry))
            {
                ShowHelpEntry(entry);
                return;
            }

            ShowHelpOverview();
        }

        private static readonly CommandHelpType[] HelpTypeOrder =
        {
            CommandHelpType.Core,
            CommandHelpType.Debug,
            CommandHelpType.Memory,
            CommandHelpType.Analysis,
            CommandHelpType.Network,
        };

        private static string GetHelpTypeLabel(CommandHelpType type)
        {
            return type switch
            {
                CommandHelpType.Core => "Core",
                CommandHelpType.Debug => "Debug",
                CommandHelpType.Memory => "Memory",
                CommandHelpType.Analysis => "Analysis",
                CommandHelpType.Network => "Network",
                _ => type.ToString(),
            };
        }

        private static void WriteColored(string text, ConsoleColor color)
        {
            if (Console.IsOutputRedirected)
            {
                Console.Write(text);
                return;
            }

            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }

        private static void WriteColoredLine(string text, ConsoleColor color)
        {
            WriteColored(text, color);
            Console.WriteLine();
        }

        private static void WriteHelpSeparator()
        {
            if (Console.IsOutputRedirected)
            {
                Console.WriteLine(new string('-', 56));
                return;
            }

            WriteColoredLine(new string('─', 56), ConsoleColor.DarkGray);
        }

        private static void ShowHelpEntry(CommandHelpEntry entry)
        {
            WriteColoredLine($"Help: {entry.Name}", ConsoleColor.Cyan);
            WriteHelpSeparator();

            WriteColored("Usage: ", ConsoleColor.DarkGray);
            WriteColoredLine(entry.Usage, ConsoleColor.Yellow);

            WriteColored("Type: ", ConsoleColor.DarkGray);
            WriteColoredLine(GetHelpTypeLabel(entry.Type), ConsoleColor.Green);

            WriteColored("Description: ", ConsoleColor.DarkGray);
            WriteColoredLine(entry.Description, ConsoleColor.White);

            if (entry.Aliases.Length > 0)
            {
                WriteColored("Aliases: ", ConsoleColor.DarkGray);
                WriteColoredLine(string.Join(", ", entry.Aliases), ConsoleColor.Cyan);
            }
        }

        private static void ShowHelpOverview()
        {
            WriteColoredLine("Type `help <command>` for command details.\n", ConsoleColor.DarkGray);

            foreach (CommandHelpType type in HelpTypeOrder)
            {
                CommandHelpEntry[] entries = CommandHelpEntries.Where(entry => entry.Type == type).ToArray();
                if (entries.Length == 0)
                    continue;

                WriteColoredLine(GetHelpTypeLabel(type), ConsoleColor.Green);
                WriteColoredLine(new string('─', 56), ConsoleColor.DarkGray);

                int CommandWidth = entries.Max(entry => entry.Name.Length);

                foreach (CommandHelpEntry cmd in entries)
                {
                    if (Console.IsOutputRedirected)
                    {
                        Console.WriteLine($"  {cmd.Name.PadRight(CommandWidth + 2)} {cmd.Description}");
                        continue;
                    }

                    Console.Write("  ");
                    WriteColored(cmd.Name.PadRight(CommandWidth + 2), ConsoleColor.Yellow);
                    WriteColoredLine(cmd.Description, ConsoleColor.Gray);
                }

                Console.WriteLine();
            }
        }

        private static void ResetUnknownBinaryLaunchOptions()
        {
            PendingUnknownLaunchMode = UnknownBinaryLaunchMode.Windows;
            PendingWindowsBlobLaunchMode = WindowsBlobLaunchMode.Direct;
            PendingGenericArch = Core.Emulation.Arch.X86;
            PendingGenericMode = Mode.MODE_32;
            PendingGenericLoadAddress = 0x10000000UL;
            PendingGenericEntryAddress = 0x10000000UL;
            PendingGenericStackSize = 0x100000UL;
        }

        private static int PromptMenuOption(int DefaultValue, params int[] ValidOptions)
        {
            string Input = Console.ReadLine()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(Input))
                return DefaultValue;

            if (!int.TryParse(Input, out int Value))
                return -1;

            for (int i = 0; i < ValidOptions.Length; i++)
            {
                if (ValidOptions[i] == Value)
                    return Value;
            }

            return -1;
        }

        private static ulong PromptHexOrDefault(string Prompt, ulong DefaultValue)
        {
            Console.Write($"{Prompt} [default: 0x{DefaultValue:X}]: ");
            string Input = Console.ReadLine()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(Input))
                return DefaultValue;

            return TryParseAddress(Input, out ulong ParsedValue, true) ? ParsedValue : DefaultValue;
        }

        private static bool SupportsIcedDisassembly()
        {
            if (Disassembler == null || Emulator == null)
                return false;

            if (Emulator.Guest is GenericGuest Generic)
                return Generic.IsX86;

            return true;
        }

        private static bool SupportsSnapshots()
        {
            if (Emulator == null)
                return false;

            if (Emulator.Guest is GenericGuest Generic)
                return Generic.IsX86;

            return true;
        }

        private static void HandlePcapCommand(string[] args)
        {
            if (args.Length == 0 || args[0].Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                if (NetworkTrafficPcapCapture.IsEnabled)
                    PrintHighlight($"[*] Network pcap capture is enabled: {NetworkTrafficPcapCapture.OutputPath} (packets: {NetworkTrafficPcapCapture.PacketCount})", true);
                else
                    PrintHighlight("[-] Network pcap capture is disabled.", true);

                return;
            }

            string action = args[0].ToLowerInvariant();
            switch (action)
            {
                case "help":
                case "?":
                    Console.WriteLine("pcap commands:");
                    Console.WriteLine("  pcap on <path>     Start dumping emulated network traffic to a pcap file.");
                    Console.WriteLine("  pcap off           Stop dumping network traffic.");
                    Console.WriteLine("  pcap status        Show the current capture state.");
                    return;

                case "on":
                    if (args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: pcap on <path>", true);
                        return;
                    }

                    string Path = string.Join(" ", args, 1, args.Length - 1);
                    if (NetworkTrafficPcapCapture.Enable(Path))
                    {
                        PrintHighlight($"[+] Network pcap capture enabled: {NetworkTrafficPcapCapture.OutputPath}", true);
                    }
                    else
                    {
                        PrintHighlight("[-] Failed to open the pcap output file.", true);
                    }
                    return;

                case "off":
                    NetworkTrafficPcapCapture.Disable();
                    PrintHighlight("[+] Network pcap capture disabled.", true);
                    return;
            }

            string TargetPath = string.Join(" ", args);
            if (string.IsNullOrWhiteSpace(TargetPath))
            {
                PrintHighlight("[-] Usage: pcap <on|off|status> [path]", true);
                return;
            }

            if (NetworkTrafficPcapCapture.Enable(TargetPath))
                PrintHighlight($"[+] Network pcap capture enabled: {NetworkTrafficPcapCapture.OutputPath}", true);
            else
                PrintHighlight("[-] Failed to open the pcap output file.", true);
        }

        private static bool TryResolveRegister(string Name, out int Register, out string RegisterName)
        {
            Register = 0;
            RegisterName = string.Empty;

            if (string.IsNullOrWhiteSpace(Name))
                return false;

            if (Emulator?.Guest is GenericGuest Generic && Generic.TryGetRegister(Name, out Register, out RegisterName))
                return true;

            foreach (FieldInfo EnumField in typeof(Registers).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                if (!EnumField.IsLiteral)
                    continue;

                string FullName = EnumField.Name;
                string ShortName = FullName.StartsWith("UC_X86_REG_", StringComparison.OrdinalIgnoreCase)
                    ? FullName.Substring("UC_X86_REG_".Length)
                    : FullName;

                if (!FullName.Equals(Name, StringComparison.OrdinalIgnoreCase) && !ShortName.Equals(Name, StringComparison.OrdinalIgnoreCase))
                    continue;

                Register = Convert.ToInt32(EnumField.GetRawConstantValue());
                RegisterName = FullName;
                return true;
            }

            return false;
        }

        private static bool TryParseWatchType(string Input, out MemoryWatchType Type)
        {
            Type = MemoryWatchType.Access;

            if (string.IsNullOrWhiteSpace(Input))
                return false;

            switch (Input.Trim().ToLowerInvariant())
            {
                case "read":
                case "r":
                    Type = MemoryWatchType.Read;
                    return true;

                case "write":
                case "w":
                    Type = MemoryWatchType.Write;
                    return true;

                case "fetch":
                case "execute":
                case "exec":
                case "x":
                case "f":
                    Type = MemoryWatchType.Fetch;
                    return true;

                case "access":
                case "rw":
                case "wr":
                case "a":
                    Type = MemoryWatchType.Access;
                    return true;
            }

            return false;
        }

        private static void ShowWatchHelp()
        {
            PrintHighlight("[*] watch usage:", true);
            Console.WriteLine("  watch                               List active watchpoints.");
            Console.WriteLine("  watch help                          Show this help text.");
            Console.WriteLine("  watch list                          List active watchpoints.");
            Console.WriteLine("  watch clear                         Remove all watchpoints.");
            Console.WriteLine("  watch add <read|write|fetch|access> <address> [size]");
            Console.WriteLine("                                       Add a watchpoint (default size: 1).");
            Console.WriteLine("  watch del <id>");
            Console.WriteLine("                                       Remove a watchpoint by id.");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  watch add write 0x140001000 8");
            Console.WriteLine("  watch add fetch some.dll+0x120");
            Console.WriteLine("  watch add access some.dll+0x120 0x20");
            Console.WriteLine("  watch del 1");
            Console.WriteLine();
        }

        private static bool EnsureGeneralMemoryHookInstalled()
        {
            if (GeneralMemoryHookHandle != IntPtr.Zero)
                return true;

            if (MemoryHook == null)
                MemoryHook = GeneralMemoryHook;

            GeneralMemoryHookHandle = Emulator._emulator.AddMemoryHook(1, 0, BackendHookType.MemoryRead | BackendHookType.MemoryWrite, MemoryHook);
            return GeneralMemoryHookHandle != IntPtr.Zero;
        }

        private static bool InstallWatchpointHooks(MemoryWatchpoint Watchpoint)
        {
            if (WatchMemoryHook == null)
                WatchMemoryHook = WatchMemoryAccessHook;

            ulong EndAddress = Watchpoint.Address + (ulong)Watchpoint.Size - 1;

            if ((Watchpoint.Type & MemoryWatchType.Read) != 0)
            {
                Watchpoint.ReadHookHandle = Emulator._emulator.AddMemoryHook(Watchpoint.Address, EndAddress, BackendHookType.MemoryRead, WatchMemoryHook);
                if (Watchpoint.ReadHookHandle == IntPtr.Zero)
                {
                    RemoveWatchpointHooks(Watchpoint);
                    return false;
                }
            }

            if ((Watchpoint.Type & MemoryWatchType.Write) != 0)
            {
                Watchpoint.WriteHookHandle = Emulator._emulator.AddMemoryHook(Watchpoint.Address, EndAddress, BackendHookType.MemoryWrite, WatchMemoryHook);
                if (Watchpoint.WriteHookHandle == IntPtr.Zero)
                {
                    RemoveWatchpointHooks(Watchpoint);
                    return false;
                }
            }

            if ((Watchpoint.Type & MemoryWatchType.Fetch) != 0)
            {
                Watchpoint.FetchHookHandle = Emulator._emulator.AddMemoryHook(Watchpoint.Address, EndAddress, BackendHookType.MemoryFetch, WatchMemoryHook);
                if (Watchpoint.FetchHookHandle == IntPtr.Zero)
                {
                    RemoveWatchpointHooks(Watchpoint);
                    return false;
                }
            }

            return true;
        }

        private static void RemoveWatchpointHooks(MemoryWatchpoint Watchpoint)
        {
            if (Watchpoint.ReadHookHandle != IntPtr.Zero)
            {
                Emulator._emulator.RemoveHook(Watchpoint.ReadHookHandle);
                Watchpoint.ReadHookHandle = IntPtr.Zero;
            }

            if (Watchpoint.WriteHookHandle != IntPtr.Zero)
            {
                Emulator._emulator.RemoveHook(Watchpoint.WriteHookHandle);
                Watchpoint.WriteHookHandle = IntPtr.Zero;
            }

            if (Watchpoint.FetchHookHandle != IntPtr.Zero)
            {
                Emulator._emulator.RemoveHook(Watchpoint.FetchHookHandle);
                Watchpoint.FetchHookHandle = IntPtr.Zero;
            }
        }

        private static void ShowFuncMonHelp()
        {
            PrintHighlight("[*] funcmon usage:", true);
            Console.WriteLine("  funcmon                               List active function monitors.");
            Console.WriteLine("  funcmon help                          Show this help text.");
            Console.WriteLine("  funcmon <address|symbol> [cc] [ArgTypes...]");
            Console.WriteLine("                                       Add or replace a function monitor.");
            Console.WriteLine("  funcmon del <address|symbol>          Remove a function monitor.");
            Console.WriteLine("  funcmon clear                         Remove all function monitors.");
            Console.WriteLine();
            Console.WriteLine("Calling conventions:");
            Console.WriteLine("  win64, cdecl, stdcall, thiscall, fastcall");
            Console.WriteLine();
            Console.WriteLine("Argument types:");
            Console.WriteLine("  ptr, u32, u64, i32, i64, ascii, wstr, string, unicode_string");
            Console.WriteLine("  string = alias for ascii");
            Console.WriteLine("  Prefix with * to dereference first, e.g. *u64, *ptr, *unicode_string");
            Console.WriteLine("  unicode_string = treat the value as a pointer to UNICODE_STRING and print its Buffer text");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  funcmon 0x140009021 ptr wstr");
            Console.WriteLine("  funcmon ntdll.dll!EtwEventWriteString win64 ptr u32 u64 wstr");
            Console.WriteLine("  funcmon ntdll.dll!LdrLoadDll win64 ptr ptr unicode_string ptr");
            Console.WriteLine("  funcmon some.dll!Func win64 *u64 *ptr *unicode_string");
            Console.WriteLine();
        }

        private static bool TryParseCommandLine(string input, out string command, out string arguments, out string[] args)
        {
            command = string.Empty;
            arguments = string.Empty;
            args = Array.Empty<string>();

            if (string.IsNullOrWhiteSpace(input))
                return false;

            string trimmed = input.Trim();
            int splitIndex = trimmed.IndexOf(' ');
            if (splitIndex < 0)
            {
                command = trimmed;
                return true;
            }

            command = trimmed.Substring(0, splitIndex);
            arguments = trimmed.Substring(splitIndex + 1).Trim();
            if (!string.IsNullOrWhiteSpace(arguments))
                args = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            return true;
        }

        private static bool ShouldReuseDebuggerStopDisplay(string Command)
        {
            return string.Equals(Command, "step", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "stepover", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ShouldFlushBufferedDebuggerInputAfterCommand(string Command)
        {
            return string.Equals(Command, "step", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "stepover", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "c", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "cont", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "continue", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "run", StringComparison.OrdinalIgnoreCase)
                || string.Equals(Command, "start", StringComparison.OrdinalIgnoreCase);
        }

        private static void HandleShowInstrsCommand(string[] args)
        {
            if (!SupportsIcedDisassembly())
            {
                PrintHighlight("[-] Instruction tracing is only available for x86/x64 sessions.", true);
                return;
            }

            if (args.Length == 0 || args[0].Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                ShowInstrsFilterEnabled = false;
                ShowInstrsModuleFilter.Clear();
                ShowInstrsRanges.Clear();
            }
            else
            {
                ShowInstrsFilterEnabled = false;
                ShowInstrsModuleFilter.Clear();
                ShowInstrsRanges.Clear();

                foreach (string ModuleName in args)
                {
                    if (TryParseAddressRange(ModuleName, out ulong RangeStart, out ulong RangeEnd))
                    {
                        ShowInstrsRanges.Add((RangeStart, RangeEnd));
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(ModuleName))
                    {
                        ShowInstrsFilterEnabled = true;
                        ShowInstrsModuleFilter.Add(ModuleName);
                    }
                }
            }

            if (InstrHookHandle == IntPtr.Zero)
            {
                InstrHookHandle = Emulator._emulator.AddCodeHook(1, 0, InstructionHook);
                if (InstrHookHandle == IntPtr.Zero)
                    PrintHighlight($"[-] Failed to install instruction tracing hook. Last unicorn error: {Emulator.GetLastError()}", true);
            }
        }

        private static void HandleHideInstrsCommand()
        {
            if (InstrHookHandle != IntPtr.Zero)
            {
                Emulator._emulator.RemoveHook(InstrHookHandle);
                InstrHookHandle = IntPtr.Zero;
            }
        }

        private static bool EnsureBreakpointHookInstalled()
        {
            if (BpHookHandle != IntPtr.Zero)
                return true;

            if (BpHook == null)
            {
                BpHook = BreakpointHandler;
            }

            BpHookHandle = Emulator._emulator.AddCodeHook(1, 0, BpHook);
            return BpHookHandle != IntPtr.Zero;
        }

        private static void RemoveBreakpointHookIfUnused()
        {
            if (Breakpoints.Count != 0 || BpHookHandle == IntPtr.Zero)
                return;

            Emulator._emulator.RemoveHook(BpHookHandle);
            BpHookHandle = IntPtr.Zero;
        }

        private static void HandleBreakpointCommand(string[] args)
        {
            if (args.Length == 0)
            {
                PrintHighlight("[-] Usage: bp <add|del|list|clear> ...");
                return;
            }

            string BpAction = args[0].ToLowerInvariant();
            if (BpAction == "list")
            {
                if (Breakpoints.Count == 0)
                {
                    PrintHighlight("[-] No breakpoints set.", true);
                    return;
                }

                PrintHighlight("[*] Breakpoints:", true);
                foreach (ulong Address in Breakpoints.OrderBy(Value => Value))
                {
                    string Condition = ConditionalBreakpoints.TryGetValue(Address, out string StoredCondition)
                        ? StoredCondition
                        : string.Empty;
                    Console.WriteLine(string.IsNullOrEmpty(Condition)
                        ? $"0x{Address:X}"
                        : $"0x{Address:X} if ({Condition})");
                }
                return;
            }

            if (BpAction == "clear")
            {
                Breakpoints.Clear();
                ConditionalBreakpoints.Clear();
                ClearBreakpointSkip();
                RemoveBreakpointHookIfUnused();
                PrintHighlight("[+] Cleared all breakpoints.", true);
                return;
            }

            if (BpAction == "del" || BpAction == "remove")
            {
                if (args.Length < 2 || !TryParseAddress(args[1], out ulong RemoveAddress))
                {
                    PrintHighlight("[-] Usage: bp del <address>", true);
                    return;
                }

                Breakpoints.Remove(RemoveAddress);
                ConditionalBreakpoints.Remove(RemoveAddress);
                if (SkipBreakpointOnce && SkipBreakpointAddress == RemoveAddress)
                    ClearBreakpointSkip();
                RemoveBreakpointHookIfUnused();
                PrintHighlight($"[+] Removed breakpoint at 0x{RemoveAddress:X}.", true);
                return;
            }

            if (BpAction == "add")
            {
                if (args.Length < 2 || !TryParseAddress(args[1], out ulong BreakAddress))
                {
                    PrintHighlight("[-] Usage: bp add <address> [condition]", true);
                    return;
                }

                string Condition = args.Length > 2 ? string.Join(' ', args.Skip(2)) : string.Empty;
                Breakpoints.Add(BreakAddress);
                if (!string.IsNullOrWhiteSpace(Condition))
                    ConditionalBreakpoints[BreakAddress] = Condition;
                else
                    ConditionalBreakpoints.Remove(BreakAddress);

                if (!EnsureBreakpointHookInstalled())
                {
                    Breakpoints.Remove(BreakAddress);
                    ConditionalBreakpoints.Remove(BreakAddress);
                    PrintHighlight($"[-] Failed to install breakpoint hook. Last unicorn error: {Emulator.GetLastError()}", true);
                    return;
                }

                PrintHighlight($"[+] Added breakpoint at 0x{BreakAddress:X}.", true);
                return;
            }

            PrintHighlight("[-] Unknown bp command. Use add, del, list, or clear.", true);
        }

        private static void HandleGhostPatchCommand(string[] args)
        {
            if (args.Length < 2)
            {
                PrintHighlight("[-] Usage: gpatch <addr> <hex-bytes|file_path>");
                return;
            }

            if (!TryParseAddress(args[0], out ulong GAddress))
            {
                PrintHighlight("[-] Invalid address", true);
                return;
            }

            string GData = string.Join(' ', args.Skip(1));
            byte[] GBytes;
            if (File.Exists(GData))
            {
                try
                {
                    GBytes = File.ReadAllBytes(GData);
                }
                catch (Exception ex)
                {
                    PrintHighlight($"[-] Failed to read from the file: {ex.Message}", true);
                    return;
                }
            }
            else if (!TryGetBytes(GData, out GBytes, out string ErrorMsg))
            {
                PrintHighlight($"[-] Couldn't get the bytes.{(string.IsNullOrEmpty(ErrorMsg) ? string.Empty : $" Error message: {ErrorMsg}")}", true);
                return;
            }

            if (GBytes.Length == 0)
            {
                PrintHighlight("[-] Ghost patch data is empty.", true);
                return;
            }

            if (GBytes.Length > uint.MaxValue || !TryGetInclusiveEnd(GAddress, (ulong)GBytes.Length, out ulong GEnd))
            {
                PrintHighlight("[-] Ghost patch range overflows the address space.", true);
                return;
            }

            if (!Emulator.IsRegionMapped(GAddress, (ulong)GBytes.Length))
            {
                PrintHighlight("[-] Region is not mapped.", true);
                return;
            }

            byte[] OriginalBytes = Emulator.ReadMemory(GAddress, (uint)GBytes.Length);

            if (!EnsureGeneralMemoryHookInstalled())
            {
                PrintHighlight($"[-] Failed to install the ghost patch memory hook, Last unicorn error: {Emulator.GetLastError()}", true);
                return;
            }

            GhostPatch Patch = new GhostPatch
            {
                Address = GAddress,
                Size = (uint)OriginalBytes.Length,
                Original = OriginalBytes,
                Patched = GBytes
            };

            Patch.BlockHookHandle = Emulator._emulator.AddCodeHook(GAddress, GEnd, GCodeHook);
            if (Patch.BlockHookHandle == IntPtr.Zero)
            {
                PrintHighlight($"[-] Failed to install the Ghost patch block hook, Last unicorn error: {Emulator.GetLastError()}", true);
                return;
            }

            GhostPatches.Add(Patch);
            GPatch = true;
            Emulator.WriteMemory(GAddress, GBytes);
            PrintHighlight($"[+] Ghost patch @ 0x{GAddress:X} ({GBytes.Length} bytes)", true);
        }

        [RequiresUnreferencedCode("Uses reflection to enumerate types and fields.")]
        [RequiresDynamicCode("Uses MakeGenericMethod which requires dynamic code.")]
        private static void HandleParseStructCommand(string[] args)
        {
            if (args.Length < 2)
            {
                PrintHighlight("[-] Usage: parse_struct <address> <struct_name>");
                return;
            }

            if (!TryParseAddress(args[0], out ulong StructAddress))
            {
                PrintHighlight("[-] Invalid address.", true);
                return;
            }

            if (string.IsNullOrEmpty(args[1]))
            {
                PrintHighlight("[-] Invalid struct name.", true);
                return;
            }

            string StructName = args[1];
            Type StructType = Assembly.GetExecutingAssembly().GetTypes().FirstOrDefault(T => T.IsValueType && !T.IsEnum && T.Namespace == "Brovan.Core.Emulation.OS.Windows" && T.Name.Equals(StructName, StringComparison.OrdinalIgnoreCase));
            if (StructType == null)
            {
                PrintHighlight($"[-] Struct \"{args[1]}\" not found.", true);
                return;
            }

            MethodInfo ParseMethod = typeof(StructSerializer).GetMethods(BindingFlags.Public | BindingFlags.Static).FirstOrDefault(M =>
            M.Name == "ParseStruct" &&
            M.IsGenericMethodDefinition &&
            M.GetParameters().Length == 3 &&
            M.GetParameters()[1].ParameterType == typeof(ulong));

            if (ParseMethod == null)
            {
                PrintHighlight("[-] StructSerializer.ParseStruct<T> was not found.", true);
                return;
            }

            MethodInfo Generic = ParseMethod.MakeGenericMethod(StructType);

            object[] InvokeArgs =
            {
                Emulator,
                StructAddress,
                null
            };

            bool Success = (bool)Generic.Invoke(null, InvokeArgs);
            if (!Success)
            {
                PrintHighlight("[-] Failed to parse struct.", true);
                return;
            }

            object StructObject = InvokeArgs[2];

            foreach (var Field in StructType.GetFields(BindingFlags.Public | BindingFlags.Instance))
            {
                object Value = Field.GetValue(StructObject);

                if (Value == null)
                {
                    PrintHighlight($"    {Field.Name}: null");
                    continue;
                }

                if (Value is string Str)
                {
                    PrintHighlight($"    {Field.Name}: \"{Str}\"");
                    continue;
                }

                if (Value is byte[] Bytes)
                {
                    PrintHighlight($"    {Field.Name}: byte[{Bytes.Length}]");
                    continue;
                }

                if (Value is ulong U64)
                {
                    PrintHighlight($"    {Field.Name}: 0x{U64:X}");
                    continue;
                }

                if (Value is uint U32)
                {
                    PrintHighlight($"    {Field.Name}: 0x{U32:X}");
                    continue;
                }

                if (Value is ushort U16)
                {
                    PrintHighlight($"    {Field.Name}: 0x{U16:X}");
                    continue;
                }

                PrintHighlight($"    {Field.Name}: {Value}");
            }
        }

        private static void HandleCheckProtectionCommand(string[] args)
        {
            if (args.Length < 1)
            {
                PrintHighlight("[-] Usage: checkprot <address>", true);
                return;
            }

            if (!TryParseAddress(args[0], out ulong Address, true))
            {
                PrintHighlight("[-] Couldn't parse the address.", true);
                return;
            }

            if (!TryFindMemoryRegion(Address, out MemoryRegion MemRegion))
            {
                PrintHighlight("[-] Address isn't mapped.", true);
                return;
            }

            PrintHighlight($"[+] Address is mapped with: {MemRegion.Protections}", true);
        }

        private static string FormatHexdumpLine(ulong Address, byte[] Data, int Offset, int Width)
        {
            StringBuilder Builder = new StringBuilder(128);
            int LineLength = Math.Min(Width, Data.Length - Offset);

            Builder.Append("0x");
            Builder.Append(Address.ToString("X8"));
            Builder.Append(": ");

            for (int i = 0; i < LineLength; i++)
            {
                Builder.Append(Data[Offset + i].ToString("X2"));
                Builder.Append(' ');
            }

            Builder.Append(' ', (Width - LineLength) * 3);

            for (int i = 0; i < LineLength; i++)
            {
                byte B = Data[Offset + i];
                Builder.Append((B >= 0x20 && B <= 0x7E) ? (char)B : '.');
            }

            return Builder.ToString();
        }

        private static void SetBlobEntryPoint(ulong LoadAddress, ulong MappedBase, ulong EntryAddress)
        {
            if (LoadAddress != 0 && EntryAddress >= LoadAddress && EntryAddress - LoadAddress <= uint.MaxValue)
                Binary.EntryPoint = (uint)(EntryAddress - LoadAddress);
            else if (EntryAddress >= MappedBase && EntryAddress - MappedBase <= uint.MaxValue)
                Binary.EntryPoint = (uint)(EntryAddress - MappedBase);
            else
                Binary.EntryPoint = 0;
        }

        private static void RemoveFuncMonPendingReturns(ulong FunctionAddress)
        {
            foreach (var Entry in FuncMonPendingReturns.ToArray())
            {
                Stack<ulong> Pending = Entry.Value;
                if (!Pending.Contains(FunctionAddress))
                    continue;

                ulong[] Remaining = Pending.Reverse().Where(Address => Address != FunctionAddress).ToArray();
                Pending.Clear();
                foreach (ulong Address in Remaining)
                    Pending.Push(Address);

                if (Pending.Count != 0)
                    continue;

                FuncMonPendingReturns.Remove(Entry.Key);
                if (FuncMonReturnHooks.TryGetValue(Entry.Key, out IntPtr HookHandle))
                {
                    if (HookHandle != IntPtr.Zero)
                        Emulator._emulator.RemoveHook(HookHandle);

                    FuncMonReturnHooks.Remove(Entry.Key);
                }
            }
        }

        private static void HandleFuncMonCommand(string[] args)
        {
            if (args.Length == 0)
            {
                if (FuncMons.Count == 0)
                {
                    PrintHighlight("[*] No funcmon hooks installed.", true);
                }
                else
                {
                    PrintHighlight("[*] funcmon hooks:", true);
                    foreach (var entry in FuncMons.OrderBy(kv => kv.Key))
                    {
                        string ArgTypesList = entry.Value.ArgTypes.Count == 0 ? "-" : string.Join(" ", entry.Value.ArgTypes);
                        Console.WriteLine($"0x{entry.Key:X} | {entry.Value.Name} | {entry.Value.Convention} | {ArgTypesList}");
                    }
                }
                return;
            }

            string Sub = args[0].Trim();
            if (Sub.Equals("help", StringComparison.OrdinalIgnoreCase) || Sub.Equals("?", StringComparison.OrdinalIgnoreCase))
            {
                ShowFuncMonHelp();
                return;
            }

            if (Sub.Equals("list", StringComparison.OrdinalIgnoreCase))
            {
                if (FuncMons.Count == 0)
                {
                    PrintHighlight("[*] No funcmon hooks installed.", true);
                }
                else
                {
                    PrintHighlight("[*] funcmon hooks:", true);
                    foreach (var entry in FuncMons.OrderBy(kv => kv.Key))
                    {
                        string ArgTypesList = entry.Value.ArgTypes.Count == 0 ? "-" : string.Join(" ", entry.Value.ArgTypes);
                        Console.WriteLine($"0x{entry.Key:X} | {entry.Value.Name} | {entry.Value.Convention} | {ArgTypesList}");
                    }
                }
                return;
            }

            if (Sub.Equals("clear", StringComparison.OrdinalIgnoreCase) || Sub.Equals("off", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var entry in FuncMons.ToArray())
                {
                    if (entry.Value.HookHandle != IntPtr.Zero)
                        Emulator._emulator.RemoveHook(entry.Value.HookHandle);
                }
                foreach (var ReturnHook in FuncMonReturnHooks.Values.ToArray())
                {
                    if (ReturnHook != IntPtr.Zero)
                        Emulator._emulator.RemoveHook(ReturnHook);
                }
                FuncMons.Clear();
                FuncMonPendingReturns.Clear();
                FuncMonReturnHooks.Clear();
                PrintHighlight("[+] funcmon hooks cleared.", true);
                return;
            }

            if (Sub.Equals("del", StringComparison.OrdinalIgnoreCase) || Sub.Equals("remove", StringComparison.OrdinalIgnoreCase))
            {
                if (args.Length < 2 || !TryParseAddress(args[1], out ulong RemoveAddress))
                {
                    PrintHighlight("[-] Usage: funcmon del <address|symbol>", true);
                    return;
                }

                if (!FuncMons.TryGetValue(RemoveAddress, out var ExistingMonitor))
                {
                    PrintHighlight($"[-] No funcmon hook found at 0x{RemoveAddress:X}.", true);
                    return;
                }

                if (ExistingMonitor.HookHandle != IntPtr.Zero)
                    Emulator._emulator.RemoveHook(ExistingMonitor.HookHandle);
                RemoveFuncMonPendingReturns(RemoveAddress);
                FuncMons.Remove(RemoveAddress);
                PrintHighlight($"[+] Removed funcmon hook at 0x{RemoveAddress:X}.", true);
                return;
            }

            if (!TryParseAddress(args[0], out ulong FuncAddress))
            {
                PrintHighlight("[-] Usage: funcmon <address|symbol> [cc] [ArgTypes...] | funcmon del <address|symbol> | funcmon clear | funcmon help", true);
                return;
            }

            string Convention = GetDefaultFuncMonConvention();
            int ArgStart = 1;
            if (args.Length > 1 && IsFuncMonConvention(args[1]))
            {
                Convention = args[1].Trim().ToLowerInvariant();
                ArgStart = 2;
            }

            List<string> ArgTypes = new List<string>();
            for (int i = ArgStart; i < args.Length; i++)
                ArgTypes.Add(args[i]);

            if (FuncMonEntryHook == null)
            {
                FuncMonEntryHook = FuncMonEntryHookHandler;
            }

            if (FuncMons.TryGetValue(FuncAddress, out var OldMonitor) && OldMonitor.HookHandle != IntPtr.Zero)
            {
                Emulator._emulator.RemoveHook(OldMonitor.HookHandle);
                RemoveFuncMonPendingReturns(FuncAddress);
            }

            IntPtr EntryHook = Emulator._emulator.AddCodeHook(FuncAddress, FuncAddress, FuncMonEntryHook);
            if (EntryHook == IntPtr.Zero)
            {
                PrintHighlight($"[-] Failed to install funcmon hook at 0x{FuncAddress:X}.", true);
                return;
            }

            string FunctionName = args[0];
            FuncMons[FuncAddress] = new FuncMon
            {
                Address = FuncAddress,
                Name = FunctionName,
                Convention = Convention,
                ArgTypes = ArgTypes,
                HookHandle = EntryHook
            };
            PrintHighlight($"[+] funcmon enabled at 0x{FuncAddress:X} ({FunctionName}, {Convention}).", true);
            return;
        }

        private static void EnsureCancelKeyPressRegistered()
        {
            if (CancelKeyPressRegistered)
                return;

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Exiting = true;
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.White;
                Console.BackgroundColor = ConsoleColor.Black;
                Environment.Exit(0);
            };
            CancelKeyPressRegistered = true;
        }

        [RequiresUnreferencedCode("Uses reflection to enumerate types and invoke methods.")]
        [RequiresDynamicCode("Uses MakeGenericMethod which requires dynamic code.")]
        public static void ExecuteCommand(string Command)
        {
            if (!TryParseCommandLine(Command, out string cmd, out string arguments, out string[] args))
                return;

            string cmdKey = cmd.ToLowerInvariant();
            if (ShouldReuseDebuggerStopDisplay(cmdKey))
                PrepareDebuggerStopDisplayRefresh();
            else
                ClearDebuggerStopDisplay();

            switch (cmdKey)
            {
                case "?":
                case "help":
                case "commands":
                    ShowHelp(args);
                    break;

                case "start":
                    Emulator.Start();
                    if (!SilentMode)
                        Console.WriteLine($"Ran {Emulator.Instruction} instructions.");
                    Emulator.Instruction = 0;
                    break;

                case "run":
                    if (!PrepareDebuggerResume())
                        break;

                    if (Emulator.Guest is GenericGuest)
                    {
                        Emulator._emulator.Emulate(Emulator._emulator.ReadRegister(Emulator.IPRegister), 0, 0, 0);
                        break;
                    }

                    if (Emulator.Threads.Count == 0)
                    {
                        PrintHighlight("[!] No threads found, creating a new thread for emulation.", true);
                        ulong IP = Emulator.ReadRegister(Emulator.IPRegister);
                        EmulatedThread EmulatorThread = Emulator.CreateEmulatedThread(IP);
                        if (EmulatorThread != null)
                        {
                            PrintHighlight($"[+] Created a thread with the ID {EmulatorThread.ThreadId}.", true);
                            Emulator.LoadContext(EmulatorThread);
                        }
                        else
                        {
                            PrintHighlight($"[-] Failed to create a thread.", true);
                        }
                    }
                    else
                    {
                        uint ThreadId = (uint)Emulator.CurrentThreadId;
                        if (Emulator.Threads.TryGetValue(ThreadId, out EmulatedThread EmuThread))
                        {
                            EmuThread.Context.RIP = Emulator.ReadRegister(Emulator.IPRegister);
                            EmuThread.State = EmulatedThreadState.Running;
                            Emulator.Threads[ThreadId] = EmuThread;
                        }
                    }

                    Emulator.RunMlfqScheduler();
                    if (!SilentMode)
                        Console.WriteLine($"Ran {Emulator.Instruction} instructions.");
                    Emulator.Instruction = 0;
                    break;

                case "cls":
                case "clear":
                    ClearConsole();
                    break;

                case "exit":
                case "quit":
                    Console.ResetColor();
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.BackgroundColor = ConsoleColor.Black;
                    Environment.Exit(0);
                    break;

                case "showinstrs":
                    HandleShowInstrsCommand(args);
                    break;

                case "bp":
                case "break":
                    HandleBreakpointCommand(args);
                    break;

                case "watch":
                case "wp":
                    if (args.Length == 0 || args[0].Equals("list", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Watchpoints.Count == 0)
                        {
                            PrintHighlight("[-] No watchpoints set.", true);
                            break;
                        }

                        PrintHighlight("[*] Watchpoints:", true);
                        foreach (MemoryWatchpoint Watchpoint in Watchpoints.Values.OrderBy(Value => Value.Id))
                            Console.WriteLine($"#{Watchpoint.Id}: {FormatWatchType(Watchpoint.Type)} 0x{Watchpoint.Address:X} size=0x{Watchpoint.Size:X}");
                        break;
                    }

                    string WatchAction = args[0].ToLowerInvariant();
                    if (WatchAction == "help")
                    {
                        ShowWatchHelp();
                        break;
                    }

                    if (WatchAction == "clear")
                    {
                        foreach (MemoryWatchpoint Watchpoint in Watchpoints.Values)
                            RemoveWatchpointHooks(Watchpoint);

                        Watchpoints.Clear();
                        PrintHighlight("[+] Cleared all watchpoints.", true);
                        break;
                    }

                    if (WatchAction == "del" || WatchAction == "remove")
                    {
                        if (args.Length < 2 || !int.TryParse(args[1], out int WatchId))
                        {
                            PrintHighlight("[-] Usage: watch del <id>", true);
                            break;
                        }

                        if (!Watchpoints.TryGetValue(WatchId, out MemoryWatchpoint ExistingWatchpoint))
                        {
                            PrintHighlight($"[-] Watchpoint #{WatchId} was not found.", true);
                            break;
                        }

                        RemoveWatchpointHooks(ExistingWatchpoint);
                        Watchpoints.Remove(WatchId);
                        PrintHighlight($"[+] Removed watchpoint #{WatchId}.", true);
                        break;
                    }

                    if (WatchAction == "add")
                    {
                        if (args.Length < 3 || !TryParseWatchType(args[1], out MemoryWatchType WatchType) || !TryParseAddress(args[2], out ulong WatchAddress))
                        {
                            PrintHighlight("[-] Usage: watch add <read|write|fetch|access> <address> [size]", true);
                            break;
                        }

                        uint WatchSize = 1;
                        if (args.Length > 3)
                        {
                            if (!TryParseAddress(args[3], out ulong ParsedWatchSize) || ParsedWatchSize == 0 || ParsedWatchSize > uint.MaxValue)
                            {
                                PrintHighlight("[-] Invalid watchpoint size.", true);
                                break;
                            }

                            WatchSize = (uint)ParsedWatchSize;
                        }

                        if (WatchAddress > ulong.MaxValue - (ulong)WatchSize + 1)
                        {
                            PrintHighlight("[-] Watchpoint range overflows the address space.", true);
                            break;
                        }

                        MemoryWatchpoint Watchpoint = new()
                        {
                            Id = NextWatchpointId++,
                            Address = WatchAddress,
                            Size = WatchSize,
                            Type = WatchType
                        };

                        if (!InstallWatchpointHooks(Watchpoint))
                        {
                            PrintHighlight($"[-] Failed to install the watchpoint hook(s), Last unicorn error: {Emulator.GetLastError()}", true);
                            break;
                        }

                        Watchpoints[Watchpoint.Id] = Watchpoint;
                        PrintHighlight($"[+] Added {FormatWatchType(Watchpoint.Type)} watchpoint #{Watchpoint.Id} at 0x{Watchpoint.Address:X} (size: 0x{Watchpoint.Size:X}).", true);
                        break;
                    }

                    PrintHighlight("[-] Unknown watch command. Use add, del, list, clear, or help.", true);
                    break;

                case "step":
                    {
                        RestoreDebuggerPause();
                        ulong CurrentIp = Emulator.ReadRegister(Emulator.IPRegister);
                        if (StepCurrentInstruction(Breakpoints.Contains(CurrentIp)))
                            ShowDebuggerStopContext("Stopped", Emulator.ReadRegister(Emulator.IPRegister));
                        break;
                    }

                case "stepover":
                    {
                        if (!SupportsIcedDisassembly())
                        {
                            PrintHighlight("[-] stepover is only available for x86/x64 sessions.", true);
                            break;
                        }

                        RestoreDebuggerPause();
                        ulong CurrentIp = Emulator.ReadRegister(Emulator.IPRegister);
                        if (!TryDecodeInstructionAt(CurrentIp, out X86Instruction Instruction, out _))
                        {
                            PrintHighlight("[-] Unable to decode instruction for stepover.", true);
                            break;
                        }

                        if (!IsCallInstruction(Instruction))
                        {
                            if (StepCurrentInstruction(Breakpoints.Contains(CurrentIp)))
                                ShowDebuggerStopContext("Stopped", Emulator.ReadRegister(Emulator.IPRegister));
                            break;
                        }

                        ArmCurrentBreakpointSkip();
                        TempStepTarget = Instruction.Address + Instruction.BytesLength;
                        if (TempStepHookHandle != IntPtr.Zero)
                        {
                            Emulator._emulator.RemoveHook(TempStepHookHandle);
                            TempStepHookHandle = IntPtr.Zero;
                        }

                        if (StepHookDelegate == null)
                        {
                            StepHookDelegate = StepHandler;
                        }

                        TempStepHookHandle = Emulator._emulator.AddCodeHook(1, 0, StepHookDelegate);
                        if (TempStepHookHandle == IntPtr.Zero)
                        {
                            TempStepTarget = 0;
                            ClearBreakpointSkip();
                            PrintHighlight($"[-] Failed to install the temporary step hook. Last unicorn error: {Emulator.GetLastError()}", true);
                            break;
                        }

                        Emulator.StartEmulation(CurrentIp, 0);
                        break;
                    }

                case "hideinstrs":
                    HandleHideInstrsCommand();
                    break;

                case "dumpconsole":
                    DumpConsole();
                    break;

                case "dumpregs":
                    Console.WriteLine(Emulator.GetDump());
                    break;

                case "pcap":
                    HandlePcapCommand(args);
                    break;

                case "threads":
                case "thread":
                case "t":
                    HandleThreadsCommand(args, arguments);
                    break;

                case "handles":
                case "handle":
                case "fds":
                case "fd":
                    HandleHandlesCommand(args, arguments);
                    break;

                case "snap":
                    if (!SupportsSnapshots())
                    {
                        PrintHighlight("[-] Snapshots are currently only available for x86/x64 sessions.", true);
                        break;
                    }

                    Snapshot = Emulator.TakeSnapshot();
                    PrintHighlight(Snapshot != null ? "[+] Snapshot taken." : "[-] Failed to take snapshot.", true);
                    break;

                case "restore":
                    if (!SupportsSnapshots())
                    {
                        PrintHighlight("[-] Snapshots are currently only available for x86/x64 sessions.", true);
                        break;
                    }

                    if (Snapshot == null)
                        PrintHighlight("[-] No snapshot available.", true);
                    else
                    {
                        Emulator.RestoreSnapshot(Snapshot);
                        PrintHighlight("[+] Snapshot restored.", true);
                    }
                    break;

                case "set":
                    {
                        if (args.Length < 2)
                        {
                            PrintHighlight("[-] Usage: set <register> <value>");
                            return;
                        }

                        if (!TryParseAddress(args[1], out ulong ParsedValue))
                        {
                            PrintHighlight("[-] Invalid value.", true);
                            break;
                        }

                        if (!TryResolveRegister(args[0], out int Register, out string RegisterName))
                        {
                            PrintHighlight("[-] Register not found.", true);
                            break;
                        }

                        if (Emulator._emulator.WriteRegister(Register, ParsedValue))
                            PrintHighlight($"[+] Wrote to {RegisterName}", true);
                        else
                            PrintHighlight("[-] Failed to write the register.", true);
                    }
                    break;

                case "get":
                    {
                        if (args.Length < 1)
                        {
                            PrintHighlight("[-] Usage: get <register>");
                            return;
                        }

                        if (!TryResolveRegister(args[0], out int Register, out string RegisterName))
                        {
                            PrintHighlight("[-] Register not found.", true);
                            break;
                        }

                        ulong Value = Emulator._emulator.ReadRegister(Register);
                        PrintHighlight($"[+] Register {RegisterName}: 0x{Value:X}");
                    }
                    break;

                case "modules":
                    if (Binary.FileFormat == BinaryFormat.PE)
                    {
                        if (Emulator.WinHelper.WinModules.Count == 0)
                        {
                            PrintHighlight("[-] No modules are loaded.");
                            break;
                        }

                        foreach (WinModule Module in Emulator.WinHelper.WinModules)
                        {
                            Console.WriteLine($"{Module.Name} {Module.Path} 0x{Module.MappedBase:X}");
                        }
                    }
                    else if (Binary.FileFormat == BinaryFormat.ELF)
                    {
                        LinuxGuest Linux = Emulator.Guest as LinuxGuest;
                        if (Linux == null || Linux.LoadedModules.Count == 0)
                        {
                            PrintHighlight("[-] No ELF modules are loaded.", true);
                            break;
                        }

                        foreach (LinuxLoadedModule Module in Linux.LoadedModules.OrderBy(Module => Module.MappedBase))
                        {
                            Console.WriteLine($"[{Module.Role}] {Module.Name} {Module.Path} 0x{Module.MappedBase:X} size=0x{Module.Size:X} entry=0x{Module.EntryPoint:X}");
                        }
                    }
                    break;

                case "hexdump":
                    if (args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: hexdump <address> <size>", true);
                        break;
                    }

                    if (!TryParseAddress(args[0], out ulong HexAddr))
                    {
                        PrintHighlight("[-] Couldn't parse the address.", true);
                        break;
                    }

                    if (!TryParseAddress(args[1], out ulong HexSize))
                    {
                        PrintHighlight("[-] Couldn't parse the size.", true);
                        break;
                    }

                    if (!Emulator.IsRegionMapped(HexAddr, HexSize))
                    {
                        PrintHighlight("[-] Region is not mapped.", true);
                        break;
                    }

                    try
                    {
                        byte[] Data = Emulator.ReadMemory(HexAddr, (uint)HexSize);
                        const int Width = 16;

                        for (int i = 0; i < Data.Length; i += Width)
                            Console.WriteLine(FormatHexdumpLine(HexAddr + (ulong)i, Data, i, Width));
                    }
                    catch (Exception ex)
                    {
                        PrintHighlight($"[-] Error dumping memory: {ex.Message}");
                    }
                    break;

                case "disasm":
                    if (!SupportsIcedDisassembly())
                    {
                        PrintHighlight("[-] Disassembly is only available for x86/x64 sessions.", true);
                        break;
                    }

                    if (args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: disasm <address> <size>", true);
                        break;
                    }

                    if (TryParseAddress(args[0], out ulong DisasmAddress))
                    {
                        if (!TryParseAddress(args[1], out ulong DisasmSize))
                        {
                            PrintHighlight("[-] Couldn't parse size.", true);
                            break;
                        }

                        if (!Emulator.IsRegionMapped(DisasmAddress, DisasmSize))
                        {
                            PrintHighlight("[-] Region is not mapped.", true);
                            break;
                        }

                        byte[] DisasmData = Emulator.ReadMemory(DisasmAddress, (uint)DisasmSize);
                        if (DisasmData.Length == 0)
                        {
                            PrintHighlight($"[-] Failed to read memory at 0x{DisasmAddress:X}", true);
                            break;
                        }

                        X86Instruction[] Instructions = Disassembler.DisassembleBinary(DisasmData, DisasmAddress, Binary, 0, true);
                        if (Instructions.Length == 0)
                        {
                            string Disassembled = Disassembler.DisassembleToStringEmu(DisasmData, DisasmAddress, Binary, 0, true);
                            Console.WriteLine($"\n{Disassembled}\n");
                            break;
                        }

                        Console.WriteLine();
                        PrintHighlightedDisassembly(Instructions, true, true);
                        Console.WriteLine();
                    }
                    else
                    {
                        PrintHighlight("[-] Couldn't parse the address.", true);
                    }
                    break;

                case "debug":
                    if (Debug)
                    {
                        Debug = false;
                        Emulator.Debug = false;
                    }
                    else
                    {
                        Debug = true;
                        Emulator.Debug = true;
                    }
                    break;

                case "memwrite":
                    if (args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: memwrite <addr> <hex-bytes|file_path>", true);
                        break;
                    }

                    if (!TryParseAddress(args[0], out ulong WAddress))
                    {
                        PrintHighlight("[-] Invalid address", true);
                        break;
                    }

                    string WData = string.Join(' ', args.Skip(1));
                    try
                    {
                        if (File.Exists(WData))
                        {
                            try
                            {
                                byte[] Data = File.ReadAllBytes(WData);
                                if (!Emulator.IsRegionMapped(WAddress, (uint)Data.Length))
                                {
                                    PrintHighlight("[-] Region is not mapped.", true);
                                    break;
                                }
                                PrintHighlight(Emulator.WriteMemory(WAddress, Data) ? "[+] Write successful." : $"[-] Failed to write, Last Error: {Emulator.GetLastError()}.", true);
                            }
                            catch (Exception ex)
                            {
                                PrintHighlight($"[-] Failed to read from the file: {ex.Message}", true);
                            }
                        }
                        else
                        {
                            if (TryGetBytes(WData, out byte[] WBytes, out string Error))
                            {
                                if (!Emulator.IsRegionMapped(WAddress, (uint)WBytes.Length))
                                {
                                    PrintHighlight("[-] Region is not mapped.", true);
                                    break;
                                }
                                PrintHighlight(Emulator.WriteMemory(WAddress, WBytes) ? "[+] Write successful." : $"[-] Failed to write, Last Error: {Emulator.GetLastError()}.", true);
                            }
                            else
                            {
                                PrintHighlight($"[-] Couldn't get the bytes.{(string.IsNullOrEmpty(Error) ? string.Empty : $" Error message: {Error}")}", true);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Error writing/parsing the hex value: {ex.Message}");
                    }

                    break;

                case "gpatch":
                    HandleGhostPatchCommand(args);
                    break;

                case "parse_struct":
                    HandleParseStructCommand(args);
                    break;
                case "write_struct":
                    if (args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: write_struct [address] <struct_name> <field=value&...>");
                        break;
                    }

                    int StructNameIndex = 0;
                    ulong StructAddress = 0;
                    if (TryParseAddress(args[0], out ulong maybeAddress))
                    {
                        StructAddress = maybeAddress;
                        StructNameIndex = 1;
                    }

                    if (args.Length <= StructNameIndex)
                    {
                        PrintHighlight("[-] Usage: write_struct [address] <struct_name> <field=value&...>");
                        break;
                    }

                    string WriteStructName = args[StructNameIndex];
                    string FieldAssignments = string.Join(' ', args.Skip(StructNameIndex + 1));
                    if (string.IsNullOrWhiteSpace(FieldAssignments))
                    {
                        PrintHighlight("[-] Provide field assignments in the form Field=Value&Field2=Value2.", true);
                        break;
                    }

                    Type WriteStructType = Assembly.GetExecutingAssembly()
                        .GetTypes()
                        .FirstOrDefault(T => T.IsValueType && !T.IsEnum && T.Namespace == "Brovan.Core.Emulation.OS.Windows" && T.Name.Equals(WriteStructName, StringComparison.OrdinalIgnoreCase));
                    if (WriteStructType == null)
                    {
                        PrintHighlight($"[-] Struct \"{WriteStructName}\" not found.", true);
                        break;
                    }

                    if (!TryBuildStructInstance(WriteStructType, FieldAssignments, out object structInstance, out string structError))
                    {
                        PrintHighlight($"[-] Failed to build struct instance: {structError}", true);
                        break;
                    }

                    MethodInfo SizeMethod = typeof(StructSerializer)
                        .GetMethods(BindingFlags.Public | BindingFlags.Static)
                        .FirstOrDefault(M => M.Name == "GetStructSize" && M.IsGenericMethodDefinition && M.GetParameters().Length == 1 && M.GetParameters()[0].ParameterType == typeof(BinaryEmulator));
                    if (SizeMethod == null)
                    {
                        PrintHighlight("[-] StructSerializer.GetStructSize<T> was not found.", true);
                        break;
                    }

                    MethodInfo GenericSizeMethod = SizeMethod.MakeGenericMethod(WriteStructType);
                    object SizeObject = GenericSizeMethod.Invoke(null, new object[] { Emulator });
                    if (SizeObject == null)
                    {
                        PrintHighlight("[-] Failed to get struct size.", true);
                        break;
                    }

                    ulong StructSize = Convert.ToUInt64(SizeObject);

                    if (StructAddress == 0)
                    {
                        StructAddress = Emulator.MapUniqueAddress(StructSize, MemoryProtection.ReadWrite);
                    }

                    if (StructAddress == 0)
                    {
                        PrintHighlight("[-] Failed to allocate memory for struct.", true);
                        break;
                    }

                    if (!Emulator.IsRegionMapped(StructAddress, StructSize))
                    {
                        PrintHighlight("[-] Target memory region is not mapped.", true);
                        break;
                    }

                    MethodInfo WriteMethod = typeof(StructSerializer)
                        .GetMethods(BindingFlags.Public | BindingFlags.Static)
                        .FirstOrDefault(M => M.Name == "WriteStruct" && M.IsGenericMethodDefinition && M.GetParameters().Length == 3 && M.GetParameters()[0].ParameterType == typeof(BinaryEmulator) && M.GetParameters()[1].ParameterType == typeof(ulong));
                    if (WriteMethod == null)
                    {
                        PrintHighlight("[-] StructSerializer.WriteStruct<T> was not found.", true);
                        break;
                    }

                    MethodInfo GenericWriteMethod = WriteMethod.MakeGenericMethod(WriteStructType);
                    object writeResultObject = GenericWriteMethod.Invoke(null, new object[] { Emulator, StructAddress, structInstance });
                    WriteStructResult WriteResult = writeResultObject as Brovan.Core.Emulation.OS.WriteStructResult;

                    if (WriteResult == null || !WriteResult.Success)
                    {
                        PrintHighlight($"[-] Failed to write struct: {(WriteResult == null ? "unknown error" : WriteResult.ToString())}", true);
                        break;
                    }

                    PrintHighlight($"[+] Wrote {WriteStructType.Name} ({StructSize} bytes) at 0x{StructAddress:X}.", true);
                    break;
                case "findstr":
                    if (!TryParseFindStrArguments(arguments, out string SearchText, out bool Utf16, out int MaxResults))
                    {
                        PrintHighlight("[-] Usage: findstr <text> [ascii|utf16] [max-results]");
                        break;
                    }

                    FindStringMatches(SearchText, Utf16, MaxResults);
                    break;
                case "regions":
                    ListMemoryRegions(true);
                    break;

                case "c":
                case "cont":
                case "continue":
                    {
                        if (!PrepareDebuggerResume())
                            break;

                        if (Emulator.Threads.Count > 0)
                            Emulator.RunMlfqScheduler();
                        else
                            Emulator.StartEmulation(Emulator.ReadRegister(Emulator.IPRegister), 0);
                        break;
                    }
                case "map":
                    if (args.Length < 2)
                    {
                        PrintHighlight("[-] map <address> <size>");
                        break;
                    }

                    if (!TryParseAddress(args[0], out ulong MapAddr))
                    {
                        PrintHighlight("[-] Invalid address.", true);
                        break;
                    }

                    if (!TryParseAddress(args[1], out ulong MapSize))
                    {
                        PrintHighlight("[-] Couldn't parse the size.", true);
                        break;
                    }

                    if (MapSize == 0)
                    {
                        PrintHighlight("[-] Invalid size.", true);
                        break;
                    }

                    if (MapAddr == 0)
                    {
                        MapAddr = Emulator.MapUniqueAddress(MapSize, MemoryProtection.All);
                    }
                    else
                    {
                        if (Emulator.IsRegionMapped(MapAddr, MapSize))
                        {
                            PrintHighlight("[-] Region is already mapped.", true);
                            break;
                        }
                        MapAddr = Emulator.MapMemoryRegion(MapAddr, MapSize, MemoryProtection.All);
                    }

                    if (MapAddr == 0)
                    {
                        PrintHighlight($"[-] Failed to map memory. Unicorn last error: {Emulator._emulator.GetLastError()}");
                        break;
                    }

                    PrintHighlight($"[+] Successfully mapped memory at 0x{MapAddr:X}.", true);
                    break;
                case "bininfo":
                case "binaryinfo":
                    if (IsQuickMode)
                    {
                        PrintHighlight("[-] Binary info details are unavailable in quick mode. Reload without --quick.", true);
                        break;
                    }

                    string infoTarget = args.Length > 0 ? args[0].ToLowerInvariant() : "summary";
                    switch (infoTarget)
                    {
                        case "summary":
                            ShowBinaryInfoSummary();
                            break;

                        case "functions":
                            if (Binary.FileFormat == BinaryFormat.PE && Binary.PE.DotNetStatus == DotNetStatus.DotNet)
                                ShowDotNetFunctionInfo(Binary.DotNet.DotNetFunctions, "DotNet Functions");
                            else
                                ShowFunctionInfo(Binary?.Functions, "Functions");
                            break;

                        case "exports":
                            ShowFunctionInfo(Binary?.ExportFunctions, "Exports");
                            break;

                        case "imports":
                            if (Binary?.PE?.ImportFunctions == null || Binary.PE.ImportFunctions.Count == 0)
                            {
                                PrintHighlight("[-] No imported functions found.", true);
                                break;
                            }

                            PrintHighlight($"[*] Imports ({Binary.PE.ImportFunctions.Count}):", true);
                            foreach (var import in Binary.PE.ImportFunctions.OrderBy(i => i.Key).Take(150))
                                Console.WriteLine($"0x{import.Key:X16}  {import.Value.LibraryName}!{import.Value.FunctionName}");

                            if (Binary.PE.ImportFunctions.Count > 150)
                                PrintHighlight($"[*] Showing first 150 of {Binary.PE.ImportFunctions.Count} imports.", true);
                            break;

                        case "sections":
                            if (Binary?.PE?.Sections == null || Binary.PE.Sections.Length == 0)
                            {
                                PrintHighlight("[-] No sections found.", true);
                                break;
                            }

                            PrintHighlight($"[*] Sections ({Binary.PE.Sections.Length}):", true);
                            foreach (PortableBinarySection section in Binary.PE.Sections.OrderBy(s => s.VirtualAddress))
                                Console.WriteLine($"{section.SectionName,-10} RVA=0x{section.VirtualAddress:X8} Raw=0x{section.RawOffset:X8} Size=0x{section.VirtualSize:X8}");
                            break;

                        case "dotnet":
                            if (Binary?.PE?.DotNetStatus != DotNetStatus.DotNet)
                            {
                                PrintHighlight("[-] Current binary is not a .NET assembly.", true);
                                break;
                            }

                            int DotNetFuncCount = Binary.DotNet?.DotNetFunctions?.Length ?? 0;
                            int DotNetTypeCount = Binary.DotNet?.DotNetTypes?.Length ?? 0;
                            int DotNetPropCount = Binary.DotNet?.DotNetProperties?.Length ?? 0;
                            int DotNetFieldCount = Binary.DotNet?.DotNetFields?.Length ?? 0;

                            PrintHighlight("[*] .NET metadata:", true);
                            Console.WriteLine($"Functions : {DotNetFuncCount}");
                            Console.WriteLine($"Types     : {DotNetTypeCount}");
                            Console.WriteLine($"Properties: {DotNetPropCount}");
                            Console.WriteLine($"Fields    : {DotNetFieldCount}");
                            break;

                        default:
                            PrintHighlight("[-] Usage: bininfo [summary|functions|exports|imports|sections|dotnet]", true);
                            break;
                    }
                    break;

                case "syscall":
                case "syscalls":
                    HandleSyscallCommand(args, arguments);
                    break;

                case "calltrace":
                case "ct":
                    {
                        if (args.Length == 0 || args[0].Equals("list", StringComparison.OrdinalIgnoreCase) || args[0].Equals("status", StringComparison.OrdinalIgnoreCase))
                        {
                            PrintHighlight($"[*] calltrace is {(CallTraceEnabled ? "enabled" : "disabled")}. depth={CallTraceMaxDepth}", true);
                            if (!string.IsNullOrEmpty(CallTraceLastError))
                                PrintHighlight($"[!] Last calltrace hook error: {CallTraceLastError}", true);
                            PrintAllCallStacks(CallTraceMaxDepth);
                            break;
                        }

                        string Sub = args[0].Trim().ToLowerInvariant();
                        if (Sub == "help" || Sub == "?")
                        {
                            PrintHighlight("[*] calltrace commands:", true);
                            Console.WriteLine("  calltrace on                 Enable lightweight call/ret tracing.");
                            Console.WriteLine("  calltrace off                Disable call/ret tracing.");
                            Console.WriteLine("  calltrace clear              Clear collected traced stacks.");
                            Console.WriteLine("  calltrace list               Show tracing status and collected stacks.");
                            Console.WriteLine("  calltrace depth <count>      Set maximum tracked frames per thread.");
                            break;
                        }

                        if (Sub == "on" || Sub == "enable")
                        {
                            if (Emulator == null)
                            {
                                PrintHighlight("[-] Start the emulator before enabling calltrace.", true);
                                break;
                            }

                            if (CallTraceHook == null)
                            {
                                CallTraceHook = CallTraceHookHandler;
                            }

                            if (CallTraceHookHandle == IntPtr.Zero)
                            {
                                CallTraceHookHandle = Emulator._emulator.AddCodeHook(1, 0, CallTraceHook);
                                if (CallTraceHookHandle == IntPtr.Zero)
                                {
                                    PrintHighlight("[-] Failed to install calltrace hook.", true);
                                    break;
                                }
                            }

                            CallTraceEnabled = true;
                            PrintHighlight("[+] calltrace enabled.", true);
                            break;
                        }

                        if (Sub == "off" || Sub == "disable")
                        {
                            CallTraceEnabled = false;
                            if (CallTraceHookHandle != IntPtr.Zero && Emulator != null)
                            {
                                Emulator._emulator.RemoveHook(CallTraceHookHandle);
                                CallTraceHookHandle = IntPtr.Zero;
                            }
                            PrintHighlight("[+] calltrace disabled.", true);
                            break;
                        }

                        if (Sub == "clear")
                        {
                            CallTraceStacks.Clear();
                            PrintHighlight("[+] calltrace stacks cleared.", true);
                            break;
                        }

                        if (Sub == "depth")
                        {
                            if (args.Length < 2 || !int.TryParse(args[1], out int NewDepth) || NewDepth <= 0)
                            {
                                PrintHighlight("[-] Usage: calltrace depth <positive_count>", true);
                                break;
                            }

                            CallTraceMaxDepth = Math.Clamp(NewDepth, 1, 4096);
                            foreach (List<CallTraceFrame> Frames in CallTraceStacks.Values)
                            {
                                while (Frames.Count > CallTraceMaxDepth)
                                    Frames.RemoveAt(0);
                            }
                            PrintHighlight($"[+] calltrace max depth set to {CallTraceMaxDepth}.", true);
                            break;
                        }

                        PrintHighlight("[-] Unknown calltrace command. Use calltrace help.", true);
                        break;
                    }

                case "callstack":
                case "bt":
                    {
                        uint ThreadId = Emulator != null && Emulator.CurrentThreadId >= 0 ? (uint)Emulator.CurrentThreadId : 0;
                        int MaxFrames = CallTraceMaxDepth;

                        if (args.Length > 0)
                        {
                            if (args[0].Equals("all", StringComparison.OrdinalIgnoreCase))
                            {
                                if (args.Length > 1 && int.TryParse(args[1], out int AllMaxFrames) && AllMaxFrames > 0)
                                    MaxFrames = AllMaxFrames;
                                PrintAllCallStacks(MaxFrames);
                                break;
                            }

                            if (!TryParseAddress(args[0], out ulong ParsedThreadId))
                            {
                                PrintHighlight("[-] Usage: callstack [thread_id|all] [max_frames]", true);
                                break;
                            }
                            ThreadId = (uint)ParsedThreadId;
                        }

                        if (args.Length > 1 && int.TryParse(args[1], out int ParsedMaxFrames) && ParsedMaxFrames > 0)
                            MaxFrames = ParsedMaxFrames;

                        PrintCallStack(ThreadId, MaxFrames);
                        break;
                    }

                case "funcmon":
                    HandleFuncMonCommand(args);
                    break;

                case "ldrplog":
                    {
                        if (args.Length == 0)
                        {
                            if (!LdrpLogEnabled || LdrpLogInternalAddress == 0)
                                PrintHighlight("[*] ldrplog is disabled.", true);
                            else
                                PrintHighlight($"[*] ldrplog enabled at 0x{LdrpLogInternalAddress:X}.", true);
                            break;
                        }

                        string sub = args[0].Trim();
                        if (sub.Equals("off", StringComparison.OrdinalIgnoreCase) || sub.Equals("disable", StringComparison.OrdinalIgnoreCase))
                        {
                            LdrpLogEnabled = false;
                            LdrpLogInternalAddress = 0;
                            if (LdrpLogHookHandle != IntPtr.Zero)
                            {
                                Emulator._emulator.RemoveHook(LdrpLogHookHandle);
                                LdrpLogHookHandle = IntPtr.Zero;
                            }
                            PrintHighlight("[+] ldrplog disabled.", true);
                            break;
                        }

                        if (sub.Equals("once", StringComparison.OrdinalIgnoreCase))
                        {
                            LdrpLogInternalHookHandler(Emulator.ReadRegister(Emulator.IPRegister), 0);
                            break;
                        }

                        if (!TryParseAddress(sub, out ulong addr))
                        {
                            PrintHighlight("[-] Usage: ldrplog <address>|off|once", true);
                            break;
                        }

                        LdrpLogInternalAddress = addr;
                        LdrpLogEnabled = true;

                        if (LdrpLogHook == null)
                        {
                            LdrpLogHook = LdrpLogInternalHookHandler;
                        }

                        if (LdrpLogHookHandle != IntPtr.Zero)
                        {
                            Emulator._emulator.RemoveHook(LdrpLogHookHandle);
                            LdrpLogHookHandle = IntPtr.Zero;
                        }

                        LdrpLogHookHandle = Emulator._emulator.AddCodeHook(addr, addr, LdrpLogHook);
                        if (LdrpLogHookHandle == IntPtr.Zero)
                        {
                            PrintHighlight($"[-] Failed to install ldrplog hook at 0x{addr:X}.", true);
                        }
                        else
                        {
                            PrintHighlight($"[+] ldrplog enabled at 0x{addr:X}.", true);
                        }
                        break;
                    }

                case "checkprot":
                    HandleCheckProtectionCommand(args);
                    break;
                default:
                    PrintHighlight("[-] Unrecognized command. Type \"help\" to list commands.", true);
                    break;
            }
        }

        private static void ShowData(bool Quick)
        {
            if (Binary != null && Binary.FileFormat != BinaryFormat.Unknown && Binary.Architecture == BinaryArchitecture.Unknown)
            {
                PrintHighlight($"[-] The file format is {Binary.FileFormat} but the architecture of the file is not supported.", true);
                Environment.Exit(-1);
            }

            if (Binary == null || Binary.FileFormat == BinaryFormat.Unknown)
            {
                ResetUnknownBinaryLaunchOptions();
                if (SilentMode)
                    return;

                PrintHighlight("[!] Binary format is unrecognized. We can still make this work!\n\nPlease choose your guest which will handle OS-specific actions and syscalls.", true);
                Console.Write("\n\n1: Windows\n2: Linux\n3: Generic Emulation\n\nOption: ");
                int Option = PromptMenuOption(3, 1, 2, 3);
                if (Option == -1)
                {
                    PrintHighlight("[-] Invalid option.", true);
                    Environment.Exit(-1);
                }

                PendingUnknownLaunchMode = (UnknownBinaryLaunchMode)Option;
                if (PendingUnknownLaunchMode == UnknownBinaryLaunchMode.Windows)
                {
                    PrintHighlight("[*] Choose the CPU mode for the Windows guest.", true);
                    Console.Write("\n\n1: x86\n2: x64\n\nOption: ");
                    int WindowsCpuOption = PromptMenuOption(2, 1, 2);
                    if (WindowsCpuOption == -1)
                    {
                        PrintHighlight("[-] Invalid option.", true);
                        Environment.Exit(-1);
                    }

                    PendingGenericArch = Core.Emulation.Arch.X86;
                    PendingGenericMode = WindowsCpuOption == 2 ? Mode.MODE_64 : Mode.MODE_32;
                    PendingGenericStackSize = WindowsCpuOption == 2 ? 0x200000UL : 0x100000UL;

                    PrintHighlight("[*] Choose the Windows blob startup path.", true);
                    Console.Write("\n\n1: Through ntdll.dll\n2: Direct entry\n\nOption: ");
                    int WindowsStartupOption = PromptMenuOption(2, 1, 2);
                    if (WindowsStartupOption == -1)
                    {
                        PrintHighlight("[-] Invalid option.", true);
                        Environment.Exit(-1);
                    }

                    PendingWindowsBlobLaunchMode = WindowsStartupOption == 1 ? WindowsBlobLaunchMode.Ntdll : WindowsBlobLaunchMode.Direct;
                    PendingGenericLoadAddress = PromptHexOrDefault("Load address", 0x10000000UL);
                    PendingGenericEntryAddress = PromptHexOrDefault("Initial PC", PendingGenericLoadAddress);
                    PendingGenericStackSize = PromptHexOrDefault("Stack size", PendingGenericStackSize);

                    if (PendingGenericMode == Mode.MODE_32)
                        PrintHighlight("[!] Windows x86 blob mode has the same limited syscall coverage as Windows x86 PE emulation.", true);

                    return;
                }

                if (PendingUnknownLaunchMode == UnknownBinaryLaunchMode.Linux)
                {
                    PrintHighlight("[*] Choose the CPU mode for the Linux guest.", true);
                    Console.Write("\n\n1: x86\n2: x64\n\nOption: ");
                    int LinuxCpuOption = PromptMenuOption(1, 1, 2);
                    if (LinuxCpuOption == -1)
                    {
                        PrintHighlight("[-] Invalid option.", true);
                        Environment.Exit(-1);
                    }

                    PendingGenericArch = Core.Emulation.Arch.X86;
                    PendingGenericMode = LinuxCpuOption == 2 ? Mode.MODE_64 : Mode.MODE_32;
                    PendingGenericStackSize = LinuxCpuOption == 2 ? 0x200000UL : 0x100000UL;
                    PendingGenericLoadAddress = PromptHexOrDefault("Load address", 0x10000000UL);
                    PendingGenericEntryAddress = PromptHexOrDefault("Initial PC", PendingGenericLoadAddress);
                    PendingGenericStackSize = PromptHexOrDefault("Stack size", PendingGenericStackSize);
                    return;
                }

                if (PendingUnknownLaunchMode != UnknownBinaryLaunchMode.Generic)
                    return;

                PrintHighlight("[*] Choose the CPU mode for the generic guest.", true);
                Console.Write("\n\n1: x86\n2: x64\n3: ARM\n4: Thumb\n\nOption: ");
                int CpuOption = PromptMenuOption(1, 1, 2, 3, 4);
                if (CpuOption == -1)
                {
                    PrintHighlight("[-] Invalid option.", true);
                    Environment.Exit(-1);
                }

                switch (CpuOption)
                {
                    case 1:
                        PendingGenericArch = Core.Emulation.Arch.X86;
                        PendingGenericMode = Mode.MODE_32;
                        PendingGenericStackSize = 0x100000UL;
                        break;
                    case 2:
                        PendingGenericArch = Core.Emulation.Arch.X86;
                        PendingGenericMode = Mode.MODE_64;
                        PendingGenericStackSize = 0x200000UL;
                        break;
                    case 3:
                        PendingGenericArch = Core.Emulation.Arch.ARM;
                        PendingGenericMode = Mode.ARM;
                        PendingGenericStackSize = 0x100000UL;
                        break;
                    case 4:
                        PendingGenericArch = Core.Emulation.Arch.ARM;
                        PendingGenericMode = Mode.THUMB;
                        PendingGenericStackSize = 0x100000UL;
                        break;
                }

                PendingGenericLoadAddress = PromptHexOrDefault("Load address", 0x10000000UL);
                PendingGenericEntryAddress = PromptHexOrDefault("Initial PC", PendingGenericLoadAddress);
                PendingGenericStackSize = PromptHexOrDefault("Stack size", PendingGenericStackSize);

                if (PendingGenericArch == Core.Emulation.Arch.ARM)
                    PrintHighlight("[!] Generic ARM/Thumb mode doesn't support disasm/showinstrs (because of the disassembling library limitation) / stepover / snapshots yet.", true);

                return;
            }

            if (Binary.FileFormat == BinaryFormat.PE && Binary.PE.DotNetStatus == DotNetStatus.DotNet)
            {
                PrintHighlight("[!] Brovan doesn't currently support emulating .NET CIL instructions.\nthe binary will be treated as a normal PE file in terms of emulation, You can still view .NET Methods, classes, etc.", true);
            }

            if (Binary.FileFormat == BinaryFormat.PE && Binary.Architecture == BinaryArchitecture.x86)
            {
                PrintHighlight("[!] WOW64 support is still experimental, expect missing syscalls and incorrect behaviour.");
            }

            Console.Title = $"Emulating a {Binary.FileFormat}{(Binary.PE.DotNetStatus != DotNetStatus.None ? " (DotNet)" : string.Empty)} File{(Quick ? " in Quick Mode" : string.Empty)}";

            PrintHighlight($"[*] Detected binary format: {Binary.FileFormat} | {Binary.Architecture}", true);

            if (!SilentMode && Binary.IsCorruptedBinary(out string CorruptionReason) != BinaryCorruptionStatus.Clean)
            {
                PrintHighlight($"[!] The binary might be corrupted {(!string.IsNullOrEmpty(CorruptionReason) ? $"(reason: {CorruptionReason}) " : string.Empty)}do you want to try to load it anyway (Y/N)? ");
                string Response = Console.ReadLine()?.ToLowerInvariant() ?? string.Empty;
                if (Response != "y" && Response != "yes")
                {
                    Binary.Dispose();
                    Environment.Exit(-1);
                }
            }

            if (BinaryAnalyzer.IsBinaryPacked(Binary))
                PrintHighlight("[!] The binary looks packed (high entropy).");

            if (Binary.FileFormat == BinaryFormat.PE)
            {
                if (Binary.Architecture == BinaryArchitecture.x64 && Binary.PE.OptionalHeader64.DataDirectory[1].VirtualAddress == 0 || Binary.Architecture == BinaryArchitecture.x86 && Binary.PE.OptionalHeader32.DataDirectory[1].VirtualAddress == 0)
                {
                    PrintHighlight("[!] The binary's IAT might be missing.");
                }
            }

            if (Binary.FileFormat == BinaryFormat.PE && Binary.PE.Subsystem == System.Reflection.PortableExecutable.Subsystem.Native)
            {
                var KernelImport = Binary.PE.ImportFunctions?.Values.FirstOrDefault(Func =>
                    Func.LibraryName.Equals("ntoskrnl.exe", StringComparison.OrdinalIgnoreCase) ||
                    Func.LibraryName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase));

                if (KernelImport != null && !string.IsNullOrWhiteSpace(KernelImport.Value.LibraryName))
                    PrintHighlight("[!] Brovan doesn't currently support kernel drivers or services. the binary will be treated as a normal user-mode application.", true);
            }
        }

        public static void RunEmulator(string FilePath, bool Quick, bool Silent, [AllowNull] string Command, [AllowNull] string RawProgramArguments, string[] ProgramArguments, NetworkAccessPolicy NetworkPolicyValue, bool NoHooks, EmulationBackendKind BackendKind)
        {
            SilentMode = Silent;

            EnsureCancelKeyPressRegistered();

            try
            {
                MappedMainModuleBase = 0;
                Snapshot = null;
                Disassembler = null;
                Watchpoints.Clear();
                NextWatchpointId = 1;
                WatchMemoryHook = null;
                                GeneralMemoryHookHandle = IntPtr.Zero;
                PrintHighlight("[*] Loading binary...", true);
                IsQuickMode = Quick;
                Binary = new BinaryFile(FilePath, Quick);
                ShowData(Quick);

                bool UseWindowsBlobGuest = Binary.FileFormat == BinaryFormat.Unknown && PendingUnknownLaunchMode == UnknownBinaryLaunchMode.Windows;
                bool UseLinuxBlobGuest = Binary.FileFormat == BinaryFormat.Unknown && PendingUnknownLaunchMode == UnknownBinaryLaunchMode.Linux;
                bool UseGenericGuest = Binary.FileFormat == BinaryFormat.Unknown && PendingUnknownLaunchMode == UnknownBinaryLaunchMode.Generic;
                if (UseWindowsBlobGuest || UseLinuxBlobGuest || UseGenericGuest)
                {
                    if (PendingGenericArch == Core.Emulation.Arch.X86)
                        Binary.Architecture = PendingGenericMode == Mode.MODE_64 ? BinaryArchitecture.x64 : BinaryArchitecture.x86;
                    else
                        Binary.Architecture = BinaryArchitecture.Unknown;
                }

                if (!Quick && !UseWindowsBlobGuest && !UseLinuxBlobGuest && !UseGenericGuest)
                {
                    int MinFunctions = 15000;
                    if (Binary.Functions.Length >= MinFunctions)
                    {
                        PrintHighlight($"[+] The binary {(Binary.Functions.Length == MinFunctions ? "equals to" : "have more than")} {MinFunctions} functions (binary have {Binary.Functions.Length} total). using parallel disassembly.", true);
                        PrintHighlight("[!] Note that if the binary takes a long time (or the process takes lots of resources) you can restart the emulator with the -q argument to skip analyzation.");
                    }

                    PrintHighlight("[*] Analyzing binary...", true);
                    BinaryAnalyzer.AnalyzeBinary(new AnalyzationSettings { StrictPushRetValidation = true, EnableParallelDisassembly = true, ParallelMinFunctionCount = MinFunctions }, Binary);
                }

                if (Binary.FileFormat == BinaryFormat.Unknown && !UseWindowsBlobGuest && !UseLinuxBlobGuest && !UseGenericGuest)
                {
                    PrintHighlight("[-] Unknown-format blobs are currently only supported through Windows, Linux, or Generic Emulation :(", true);
                    return;
                }

                Disassembler = Binary.Architecture == BinaryArchitecture.x86 || Binary.Architecture == BinaryArchitecture.x64 ? new IcedX86Disassembler(Binary, X86DisassemblerFormat.FastFormat) : null;

                PrintHighlight(UseWindowsBlobGuest ? "[*] Initializing Windows blob emulator..." : UseLinuxBlobGuest ? "[*] Initializing Linux blob emulator..." : UseGenericGuest ? "[*] Initializing generic emulator..." : "[*] Initializing emulator with the binary...", true);
                BinaryEmulatorSettings EmulatorSettings = new BinaryEmulatorSettings
                {
                    SplitStack = false,
                    FakeUnimplementedSyscalls = false,
                    HandleInvalidOperations = true,
                    Flags = Silent ? 0 : LogFlags.All,
                    OnMessageHandler = Silent ? null : EmulationMessageHandler,
                    InvalidOperationsCallback = InvalidOperationsCallback,
                    SyscallNotificationCallback = Silent ? null : SyscallNotification,
                    EmulateNetworking = NetworkPolicyValue.HasAnyAccess(),
                    NetworkPolicy = NetworkPolicyValue,
                    RawProgramArguments = RawProgramArguments,
                    ProgramArguments = ProgramArguments ?? Array.Empty<string>(),
                    NoHooks = NoHooks,
                    BackendKind = BackendKind
                };

                if (UseWindowsBlobGuest)
                {
                    WindowsGuest Windows = new WindowsGuest(new BlobData
                    {
                        LoadAddress = PendingGenericLoadAddress,
                        EntryAddress = PendingGenericEntryAddress,
                        StackSize = PendingGenericStackSize
                    }, PendingWindowsBlobLaunchMode);
                    Emulator = new BinaryEmulator(Windows, EmulatorSettings, PendingGenericMode, PendingGenericArch, Binary.GetBinaryData(), Binary);
                    MappedMainModuleBase = Windows.BlobMappedBase;

                    SetBlobEntryPoint(PendingGenericLoadAddress, MappedMainModuleBase, PendingGenericEntryAddress);
                }
                else if (UseLinuxBlobGuest)
                {
                    LinuxGuest Linux = new LinuxGuest(new BlobData
                    {
                        LoadAddress = PendingGenericLoadAddress,
                        EntryAddress = PendingGenericEntryAddress,
                        StackSize = PendingGenericStackSize
                    });
                    Emulator = new BinaryEmulator(Linux, EmulatorSettings, PendingGenericMode, PendingGenericArch, Binary.GetBinaryData(), Binary);
                    MappedMainModuleBase = Linux.BlobMappedBase;

                    SetBlobEntryPoint(PendingGenericLoadAddress, MappedMainModuleBase, PendingGenericEntryAddress);
                }
                else if (UseGenericGuest)
                {
                    GenericGuest Generic = new GenericGuest(PendingGenericArch, PendingGenericMode, PendingGenericLoadAddress, PendingGenericEntryAddress, PendingGenericStackSize);
                    Emulator = new BinaryEmulator(Generic, EmulatorSettings, PendingGenericMode, PendingGenericArch, Binary.GetBinaryData(), Binary);
                    MappedMainModuleBase = Generic.MappedBase;

                    SetBlobEntryPoint(PendingGenericLoadAddress, MappedMainModuleBase, PendingGenericEntryAddress);
                }
                else
                {
                    Emulator = new BinaryEmulator(Binary, EmulatorSettings);
                }
                Emulator.Syscalls.OnInteractive += HandleSyscallInteractive;
                Binary.DisposeBinaryData();
                MemoryHook = GeneralMemoryHook;
                GCodeHook = GLookupHook;

                if (MappedMainModuleBase == 0)
                {
                    if (Binary.FileFormat == BinaryFormat.PE)
                    {
                        WinModule MappedMod = Emulator.WinHelper?.WinModules.FirstOrDefault(b => b.Path == Binary.Location);
                        if (MappedMod != null)
                        {
                            MappedMainModuleBase = MappedMod.MappedBase;
                        }
                        else
                        {
                            PrintHighlight("[-] Couldn't determine the main module in memory.");
                        }
                    }
                    else if (Emulator.Guest is GenericGuest Generic)
                    {
                        MappedMainModuleBase = Generic.MappedBase;
                    }
                    else if (Emulator.Guest is LinuxGuest Linux)
                    {
                        MappedMainModuleBase = Linux.MainModuleBase;
                    }
                }
                InstructionHook = InstructionHandler;

                HidePrefix = true;
                Variables.Arch = Binary.Architecture;
                if (UseWindowsBlobGuest)
                {
                    string PcName = PendingGenericMode == Mode.MODE_64 ? "RIP" : "EIP";
                    string StartupPath = PendingWindowsBlobLaunchMode == WindowsBlobLaunchMode.Ntdll ? "ntdll.dll startup" : "direct entry";
                    PrintHighlight($"[+] Windows blob guest ready ({StartupPath}). Blob mapped at 0x{MappedMainModuleBase:X}. Use set {PcName.ToLowerInvariant()} <address>, continue, or step.", true);
                }
                else if (UseLinuxBlobGuest)
                {
                    string PcName = PendingGenericMode == Mode.MODE_64 ? "RIP" : "EIP";
                    PrintHighlight($"[+] Linux blob guest ready. Blob mapped at 0x{MappedMainModuleBase:X}. Use set {PcName.ToLowerInvariant()} <address>, continue, or step.", true);
                }
                else if (UseGenericGuest)
                {
                    string PcName = PendingGenericArch == Core.Emulation.Arch.X86 ? (PendingGenericMode == Mode.MODE_64 ? "RIP" : "EIP") : "PC";
                    PrintHighlight($"[+] Generic guest ready. Blob mapped at 0x{MappedMainModuleBase:X}. Use set {PcName.ToLowerInvariant()} <address>, continue, or step.", true);
                }

                if (!string.IsNullOrEmpty(Command))
                {
                    try
                    {
                        string[] Commands = Command.Split(';');
                        for (int i = 0; i < Commands.Length; i++)
                        {
                            Commands[i] = Commands[i].Replace("$entry", (MappedMainModuleBase + Binary.EntryPoint).ToString(), StringComparison.OrdinalIgnoreCase);

                            if (!Silent && TryPreprocessExpression(Commands[i], out string processedCommand) && TryEvaluateExpression(processedCommand, out ulong valueCommand))
                            {
                                Console.WriteLine($"0x{valueCommand:X} ({valueCommand}){(Emulator.IsRegionMapped(valueCommand, 1) ? " - Mapped" : " - Not Mapped")}");
                            }

                            if (Silent)
                            {
                                TextWriter PreviousOut = Console.Out;
                                try
                                {
                                    Console.SetOut(TextWriter.Null);
                                    ExecuteCommand(Commands[i]);
                                }
                                finally
                                {
                                    Console.SetOut(PreviousOut);
                                }
                            }
                            else
                            {
                                ExecuteCommand(Commands[i]);
                            }
                        }
                    }
                    catch
                    {
                        Command = null;
                    }
                }

                if (Silent)
                {
                    if (string.IsNullOrEmpty(Command))
                        Emulator.Start();

                    return;
                }

                while (true)
                {
                    if (Exiting)
                        break;

                    string Input;
                    if (DebuggerStopDisplayActive)
                    {
                        Input = ReadDebuggerCommandLine("Brovan Emulator > ");
                    }
                    else
                    {
                        try
                        {
                            DebuggerPromptTop = Console.CursorTop;
                        }
                        catch
                        {
                            DebuggerPromptTop = -1;
                        }

                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.Write("emu@brovan ");
                        Console.ForegroundColor = ConsoleColor.DarkMagenta;
                        Console.Write("> ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Input = Console.ReadLine()?.Trim();
                    }

                    if (string.IsNullOrWhiteSpace(Input))
                    {
                        ClearDebuggerCommandPromptLine();
                        continue;
                    }

                    Input = Input.Replace("$entry", (MappedMainModuleBase + Binary.EntryPoint).ToString(), StringComparison.OrdinalIgnoreCase);

                    if (TryPreprocessExpression(Input, out string processed) && TryEvaluateExpression(processed, out ulong value))
                    {
                        ClearDebuggerStopDisplay();
                        Console.WriteLine($"0x{value:X} ({value}){(Emulator.IsRegionMapped(value, 1) ? " - Mapped" : " - Not Mapped")}");
                        continue;
                    }

                    try
                    {
                        bool ShouldFlushBufferedInput = false;
                        if (TryParseCommandLine(Input, out string InputCommand, out _, out _))
                        {
                            ShouldFlushBufferedInput = DebuggerStopDisplayActive
                                && ShouldFlushBufferedDebuggerInputAfterCommand(InputCommand);
                            if (ShouldFlushBufferedInput)
                                FlushPendingDebuggerInput();
                        }

                        ExecuteCommand(Input);

                        if (ShouldFlushBufferedInput)
                            FlushPendingDebuggerInput();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine();
                        PrintHighlight($"[-] Unhandled exception in the command handler: {ex.Message}. Continuing execution.");
                        continue;
                    }
                }

            }
            catch (Exception ex)
            {
                LogError($"[EmulationMenu] Error in the emulation menu: {ex.Message}\n Stack trace:\n{ex.StackTrace}");
                PrintHighlight($"[-] Error in the emulation menu: {ex.Message}");
            }
        }
    }
}