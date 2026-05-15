using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Variables;
using static Brovan.Core.Helpers.Utils;
using static Brovan.Helpers;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Brovan
{
    public partial class Handlers
    {
        private const int LdrpLogMaxAscii = 0x600;
        private const int LdrpLogMaxUnicodeChars = 0x600;

        private static string FormatLdrpMessage(string fmt, ulong rsp)
        {
            if (string.IsNullOrEmpty(fmt))
                return string.Empty;

            ulong argBase = rsp + 0x30;
            int argIndex = 0;

            ulong NextArg()
            {
                ulong addr = argBase + (ulong)(argIndex * 8);
                argIndex++;
                if (!Emulator.IsRegionMapped(addr, 8))
                    return 0;
                return Emulator.ReadMemoryULong(addr);
            }

            StringBuilder sb = new StringBuilder(fmt.Length + 64);

            for (int i = 0; i < fmt.Length; i++)
            {
                char c = fmt[i];
                if (c != '%')
                {
                    sb.Append(c);
                    continue;
                }

                if (i + 1 < fmt.Length && fmt[i + 1] == '%')
                {
                    sb.Append('%');
                    i++;
                    continue;
                }

                int j = i + 1;
                bool ZeroPad = false;
                int Width = 0;
                bool IsI64 = false;

                if (j < fmt.Length && fmt[j] == '0')
                {
                    ZeroPad = true;
                    j++;
                }

                while (j < fmt.Length && char.IsDigit(fmt[j]))
                {
                    Width = (Width * 10) + (fmt[j] - '0');
                    j++;
                }

                if (j < fmt.Length && fmt[j] == 'I')
                {
                    if (j + 2 < fmt.Length && fmt[j + 1] == '6' && fmt[j + 2] == '4')
                    {
                        IsI64 = true;
                        j += 3;
                    }
                }

                while (j < fmt.Length && (fmt[j] == 'l' || fmt[j] == 'h'))
                {
                    j++;
                }

                if (j >= fmt.Length)
                {
                    sb.Append('%');
                    break;
                }

                if (fmt[j] == 'w' && j + 1 < fmt.Length && fmt[j + 1] == 'Z')
                {
                    ulong p = NextArg();
                    if (TryReadUnicodeStringStruct(p, out string uz))
                        sb.Append(uz);
                    else
                        sb.Append($"0x{p:X}");
                    i = j + 1;
                    continue;
                }

                if (fmt[j] == 'w' && j + 1 < fmt.Length && fmt[j + 1] == 's')
                {
                    ulong p = NextArg();
                    sb.Append(ReadWideZ(p));
                    i = j + 1;
                    continue;
                }

                char spec = fmt[j];
                ulong val = 0;

                switch (spec)
                {
                    case 's':
                        val = NextArg();
                        sb.Append(ReadAsciiZ(val));
                        break;
                    case 'p':
                        val = NextArg();
                        sb.Append($"0x{val:X}");
                        break;
                    case 'x':
                    case 'X':
                        val = NextArg();
                        if (!IsI64)
                            val = (uint)val;
                        string hx = val.ToString(spec == 'x' ? "x" : "X");
                        if (Width > 0)
                            hx = ZeroPad ? hx.PadLeft(Width, '0') : hx.PadLeft(Width);
                        sb.Append(hx);
                        break;
                    case 'd':
                    case 'i':
                        val = NextArg();
                        if (IsI64)
                            sb.Append(unchecked((long)val).ToString());
                        else
                            sb.Append(unchecked((int)val).ToString());
                        break;
                    case 'u':
                        val = NextArg();
                        if (IsI64)
                            sb.Append(val.ToString());
                        else
                            sb.Append(((uint)val).ToString());
                        break;
                    case 'c':
                        val = NextArg();
                        sb.Append((char)(val & 0xFF));
                        break;
                    default:
                        sb.Append('%');
                        sb.Append(spec);
                        break;
                }

                i = j;
            }

            return sb.ToString();
        }

        public static void LdrpLogInternalHookHandler(IntPtr uc, ulong Address, uint Size, IntPtr user_data)
        {
            if (!LdrpLogEnabled || LdrpLogInternalAddress == 0 || Address != LdrpLogInternalAddress)
                return;

            try
            {
                if (Variables.Arch != BinaryArchitecture.x64)
                {
                    PrintHighlight("[LDRPLOG] x86 is not supported for ldrplog yet.", false, true);
                    return;
                }

                ulong rcx = Emulator.ReadRegister(Registers.UC_X86_REG_RCX);
                ulong rdx = Emulator.ReadRegister(Registers.UC_X86_REG_RDX);
                ulong r8 = Emulator.ReadRegister(Registers.UC_X86_REG_R8);
                ulong r9 = Emulator.ReadRegister(Registers.UC_X86_REG_R9);
                ulong rsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);

                string file = ReadAsciiZ(rcx);
                int line = unchecked((int)(rdx & 0xFFFFFFFF));
                string func = ReadAsciiZ(r8);
                int level = unchecked((int)(r9 & 0xFFFFFFFF));

                ulong fmtPtrAddr = rsp + 0x28;
                ulong fmtPtr = Emulator.IsRegionMapped(fmtPtrAddr, 8) ? Emulator.ReadMemoryULong(fmtPtrAddr) : 0;
                string fmt = ReadAsciiZ(fmtPtr);

                string msg = FormatLdrpMessage(fmt, rsp);

                string prefix = $"{file}:{line} {func} (lvl {level}) ";
                PrintHighlight($"[LDRPLOG] {prefix}{msg}".TrimEnd(), false, true);
            }
            catch (Exception ex)
            {
                PrintHighlight($"[LDRPLOG] decode failed: {ex.Message}", false, true);
            }
        }

        public static void EmulationMessageHandler(string Message, LogFlags Flag)
        {
            LogFlags CheckFlags = LogFlags.Syscall | LogFlags.CPUID | LogFlags.RDTSC | LogFlags.RDTSCP;
            bool IsCheckFlag = (Flag & CheckFlags) != 0;
            if (!string.IsNullOrEmpty(Message))
            {
                bool HasPrimaryWinModule = Emulator?.WinHelper?.WinModules != null && Emulator.WinHelper.WinModules.Count > 0;
                if (IsCheckFlag && (!HasPrimaryWinModule || InsideWinModule(Emulator.ReadRegister(Emulator.IPRegister), Emulator.WinHelper.WinModules[0])))
                {
                    PrintHighlight(Message, false, HidePrefix);
                }
                else if (!IsCheckFlag)
                {
                    PrintHighlight(Message, false, HidePrefix);
                }
            }
        }

        public static bool InvalidOperationsCallback(MemoryType Type, ulong Address, uint Size, ulong value)
        {
            return false;
        }

        public static string ResolveFunctionName(ulong Address, WinModule Module)
        {
            if (Module.Exports == null || Module.Exports.Count == 0)
                return null;

            ulong Rva = Address - Module.MappedBase + Module.OriginalBase;

            ulong BestMatch = 0;
            string BestName = null;

            foreach (var Exp in Module.Exports)
            {
                ulong ExpVa = Exp.Key;

                if (ExpVa <= Rva && ExpVa >= BestMatch)
                {
                    BestMatch = ExpVa;
                    BestName = Exp.Value;
                }
            }

            if (BestName == null)
                return null;

            ulong Offset = Rva - BestMatch;
            return Offset == 0 ? BestName : $"{BestName}+0x{Offset:X}";
        }

        private static WinModule _lastAddressModule = null;
        private static ulong _lastAddressModuleStart = 0;
        private static ulong _lastAddressModuleEnd = 0;
        private static readonly byte[] InstructionDisasmBuffer = new byte[16];
        private static LinuxLoadedModule _lastLinuxAddressModule = null;
        private static ulong _lastLinuxAddressModuleStart = 0;
        private static ulong _lastLinuxAddressModuleEnd = 0;

        private static WinModule FindModuleByAddress(ulong Address)
        {
            if (Emulator?.WinHelper?.WinModules == null)
                return null;

            if (_lastAddressModule != null && Address >= _lastAddressModuleStart && Address < _lastAddressModuleEnd)
                return _lastAddressModule;

            for (int i = 0; i < Emulator.WinHelper.WinModules.Count; i++)
            {
                WinModule Module = Emulator.WinHelper.WinModules[i];
                if (Address >= Module.MappedBase && Address < Module.MappedBase + Module.SizeOfImage)
                {
                    _lastAddressModule = Module;
                    _lastAddressModuleStart = Module.MappedBase;
                    _lastAddressModuleEnd = Module.MappedBase + Module.SizeOfImage;
                    return Module;
                }
            }

            return null;
        }

        private static LinuxLoadedModule FindLinuxModuleByAddress(ulong Address)
        {
            LinuxGuest Linux = Emulator?.Guest as LinuxGuest;
            if (Linux == null || Linux.LoadedModules == null)
                return null;

            if (_lastLinuxAddressModule != null && _lastLinuxAddressModule.ContainsAddress(Address))
                return _lastLinuxAddressModule;

            for (int i = 0; i < Linux.LoadedModules.Count; i++)
            {
                LinuxLoadedModule Module = Linux.LoadedModules[i];
                if (Module.ContainsAddress(Address))
                {
                    _lastLinuxAddressModule = Module;
                    _lastLinuxAddressModuleStart = Module.MappedBase;
                    _lastLinuxAddressModuleEnd = Module.MappedBase + Module.Size;
                    return Module;
                }
            }

            return null;
        }

        public static void InstructionHandler(IntPtr uc, ulong Address, uint Size, IntPtr user_data)
        {
            WinModule Module = null;
            LinuxLoadedModule LinuxModule = null;

            if (Binary.FileFormat == BinaryFormat.PE && Emulator?.WinHelper?.WinModules != null)
            {
                Module = FindModuleByAddress(Address);
                if (!IsShowInstrsAllowed(Address, Module))
                    return;
            }
            else if (Binary.FileFormat == BinaryFormat.ELF)
            {
                LinuxModule = FindLinuxModuleByAddress(Address);
                if (!IsShowInstrsAllowed(Address, LinuxModule?.Name, LinuxModule?.Path))
                    return;
            }
            else if (!IsShowInstrsAllowed(Address, (WinModule)null))
            {
                return;
            }

            int InstructionSize = Size > (uint)InstructionDisasmBuffer.Length ? InstructionDisasmBuffer.Length : (int)Size;
            if (InstructionSize == 0)
                return;

            if (!Emulator.ReadMemory(Address, InstructionDisasmBuffer.AsSpan(0, InstructionSize), (uint)InstructionSize))
                return;

            if (InstructionSize < InstructionDisasmBuffer.Length)
                Array.Clear(InstructionDisasmBuffer, InstructionSize, InstructionDisasmBuffer.Length - InstructionSize);

            if (Disassembler == null)
            {
                Console.WriteLine($"0x{Address:X}: <disassembly unavailable>");
                return;
            }

            string disasm = Disassembler.DisassembleToStringEmu(InstructionDisasmBuffer, Address, Emulator._binary, 1, false);

            string FunctionInfo = null;

            if (Module != null)
            {
                FunctionInfo = ResolveFunctionName(Address, Module);
            }

            if (Module != null && FunctionInfo != null)
            {
                Console.WriteLine($"(MODULE: {Module.Name} | FUNC: {FunctionInfo}) " + $"0x{Address:X}: {disasm}");
            }
            else if (Module != null)
            {
                Console.WriteLine($"(MODULE: {Module.Name}) " + $"0x{Address:X}: {disasm}");
            }
            else if (LinuxModule != null)
            {
                Console.WriteLine($"(MODULE: {LinuxModule.Name} | ROLE: {LinuxModule.Role}) " + $"0x{Address:X}: {disasm}");
            }
            else
            {
                Console.WriteLine($"0x{Address:X}: {disasm}");
            }
        }

        private static string FormatSyscallReturnStatus(ulong ReturnStatus)
        {
            if (Binary != null && Binary.FileFormat == BinaryFormat.PE)
            {
                NTSTATUS Status = (NTSTATUS)(uint)ReturnStatus;
                if (Enum.IsDefined(typeof(NTSTATUS), Status))
                    return Status.ToString();
            }

            return $"0x{ReturnStatus:X}";
        }

        public static void SyscallNotification(ulong Address, ulong Syscall, string Name, ulong ReturnStatus)
        {
            if (Name == null)
            {
                PrintHighlight($"[!] Unimplemented syscall number 0x{Syscall:X}");
            }

            if (Binary.FileFormat == BinaryFormat.PE && Emulator?.WinHelper?.WinModules != null && Emulator.WinHelper.WinModules.Count > 0)
            {
                WinModule Module = Emulator.WinHelper.WinModules[0];
                if (Module != null)
                {
                    if (true || Debug || InsideWinModule(Address, Module))
                    {
                        ulong IP = Emulator.ReadRegister(Emulator.IPRegister);
                        string ReturnStatusString = FormatSyscallReturnStatus(ReturnStatus);
                        WinModule CurrentModule = Emulator.WinHelper.WinModules.FirstOrDefault(Mod => IP >= Mod.MappedBase && IP <= Mod.MappedBase + Mod.SizeOfImage);
                        string ModuleName = CurrentModule != null ? CurrentModule.Name : "unknown";
                        PrintHighlight($"[*] [{ModuleName}] {(string.IsNullOrEmpty(Name) ? $"Unimplemented syscall with the number {Syscall:X}" : $"Syscall {Name}")} (0x{Syscall:X}) executed, returned {ReturnStatusString}.", false, true);
                    }
                }
            }
        }

        public static void GLookupHook(IntPtr uc, ulong Address, uint Size, IntPtr user_data)
        {
            foreach (GhostPatch Patch in GhostPatches)
            {
                if (!TryGetInclusiveEnd(Patch.Address, Patch.Size, out ulong PatchEnd))
                    continue;

                if (Address >= Patch.Address && Address <= PatchEnd)
                    Emulator.WriteMemory(Patch.Address, Patch.Patched);
            }
        }

        private static bool IsWatchedMemoryType(MemoryType type, MemoryWatchType watchType)
        {
            if (type == MemoryType.UC_MEM_READ)
                return (watchType & MemoryWatchType.Read) != 0;

            if (type == MemoryType.UC_MEM_WRITE)
                return (watchType & MemoryWatchType.Write) != 0;

            if (type == MemoryType.UC_MEM_FETCH)
                return (watchType & MemoryWatchType.Fetch) != 0;

            return false;
        }

        private static bool IsWatchpointMatch(MemoryWatchpoint watchpoint, MemoryType type, ulong address, uint size)
        {
            if (!IsWatchedMemoryType(type, watchpoint.Type))
                return false;

            if (!TryGetInclusiveEnd(address, Math.Max(size, 1U), out ulong accessEnd))
                accessEnd = ulong.MaxValue;

            if (!TryGetInclusiveEnd(watchpoint.Address, Math.Max(watchpoint.Size, 1U), out ulong watchEnd))
                watchEnd = ulong.MaxValue;

            return address <= watchEnd && accessEnd >= watchpoint.Address;
        }

        private static bool HandleWatchpoints(MemoryType type, ulong address, uint size, ulong value)
        {
            if (Watchpoints.Count == 0)
                return false;

            bool handled = false;
            ulong ip = Emulator.ReadRegister(Emulator.IPRegister);

            foreach (MemoryWatchpoint watchpoint in Watchpoints.Values)
            {
                if (!IsWatchpointMatch(watchpoint, type, address, size))
                    continue;

                string message = $"[!] Watchpoint #{watchpoint.Id} {FormatWatchType(type == MemoryType.UC_MEM_READ ? MemoryWatchType.Read : type == MemoryType.UC_MEM_WRITE ? MemoryWatchType.Write : MemoryWatchType.Fetch)} hit at 0x{address:X}";
                if (size > 1)
                    message += $" (size: 0x{size:X})";

                message += $" from 0x{ip:X}";

                if (type == MemoryType.UC_MEM_WRITE)
                {
                    string digits = checked((int)Math.Min(size, 8) * 2).ToString();
                    message += $", value=0x{value.ToString($"X{digits}")}";
                    if (size > 8)
                        message += " (truncated)";
                }

                PrintHighlight(message + ".", true);
                handled = true;
            }

            return handled;
        }

        public static bool WatchMemoryAccessHook(IntPtr uc, MemoryType Type, ulong Address, uint Size, ulong value, IntPtr user_data)
        {
            HandleWatchpoints(Type, Address, Size, value);
            return true;
        }

        public static bool GeneralMemoryHook(IntPtr uc, MemoryType Type, ulong Address, uint Size, ulong value, IntPtr user_data)
        {
            ulong IP = Emulator.ReadRegister(Emulator.IPRegister);
            if (Binary.FileFormat == BinaryFormat.PE)
            {
                if (Display(Address, Emulator.PEB, IP))
                {
                    PrintHighlight($"[*] {GetAction(Type)} the PEB at offset 0x{(Address - Emulator.PEB).ToString("X")} at 0x{IP:X}", false, true);
                }

                ulong Teb = Emulator.TEB;
                if (Display(Address, Teb, IP))
                {
                    PrintHighlight($"[*] {GetAction(Type)} the TEB at offset 0x{(Address - Teb).ToString("X")} at 0x{IP:X}", false, true);
                }

                if (Display(Address, Emulator.KUSER_SHARED_DATA, IP))
                {
                    PrintHighlight($"[*] {GetAction(Type)} KUSER_SHARED_DATA at offset 0x{(Address - Emulator.KUSER_SHARED_DATA).ToString("X")} at 0x{IP:X}", false, true);
                }
            }

            if (GPatch && (Type == MemoryType.UC_MEM_READ || Type == MemoryType.UC_MEM_WRITE))
            {
                List<GhostPatch>? WrittenPatches = null;
                foreach (GhostPatch Patch in GhostPatches)
                {
                    if (!TryGetInclusiveEnd(Patch.Address, Patch.Size, out ulong PatchEnd))
                        continue;

                    ulong AccessSize = Math.Max(Size, 1U);
                    if (!TryGetInclusiveEnd(Address, AccessSize, out ulong AccessEnd))
                        AccessEnd = ulong.MaxValue;

                    if (Address > PatchEnd || AccessEnd < Patch.Address)
                        continue;

                    Emulator.WriteMemory(Patch.Address, Patch.Original);
                    if (Type == MemoryType.UC_MEM_READ)
                    {
                        PrintHighlight($"[$] Ghost patch was hidden from a memory read at 0x{IP:X}.", false, true);
                    }
                    else
                    {
                        WrittenPatches ??= new List<GhostPatch>();
                        WrittenPatches.Add(Patch);
                        PrintHighlight($"[$] Ghost patch at 0x{Patch.Address:X} was restored and disabled before a memory write at 0x{IP:X}.", false, true);
                    }
                }

                if (WrittenPatches != null)
                {
                    foreach (GhostPatch Patch in WrittenPatches)
                    {
                        if (Patch.BlockHookHandle != IntPtr.Zero)
                        {
                            Emulator._emulator.RemoveHook(Patch.BlockHookHandle);
                            Patch.BlockHookHandle = IntPtr.Zero;
                        }

                        GhostPatches.Remove(Patch);
                    }

                    GPatch = GhostPatches.Count != 0;
                }
            }
            return true;
        }

        public static void HandleSyscallInteractive(SyscallContext ctx)
        {
            string name = string.IsNullOrWhiteSpace(ctx.Name) ? $"sys_{ctx.Number:X}" : ctx.Name;
            Console.WriteLine();
            PrintHighlight($"[SYSCALL INTERACTIVE] {name} (0x{ctx.Number:X})", true);
            Console.WriteLine($"Args: {string.Join(", ", ctx.Args.Select(a => $"0x{a:X}"))}");
            Console.Write("Action [allow|deny|return <value>]: ");
            string input = Console.ReadLine()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(input))
                return;

            string[] parts = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
                return;

            string action = parts[0].ToLowerInvariant();
            if (action == "allow")
            {
                ctx.Handled = false;
                return;
            }

            if (action == "deny")
            {
                ctx.ReturnValue = parts.Length > 1 && TryParseAddress(parts[1], out ulong returnValue)
                    ? returnValue
                    : (ulong)(uint)NTSTATUS.STATUS_ACCESS_DENIED;
                ctx.Handled = true;
                return;
            }

            if (action == "return" && parts.Length > 1 && TryParseAddress(parts[1], out ulong ret))
            {
                ctx.ReturnValue = ret;
                ctx.Handled = true;
            }
        }

        public static void BreakpointHandler(IntPtr uc, ulong Address, uint Size, IntPtr user_data)
        {
            if (BreakpointsSuppressed || ShouldSkipBreakpoint(Address))
                return;

            if (!Breakpoints.Contains(Address))
                return;

            if (ConditionalBreakpoints.TryGetValue(Address, out string Condition) && !string.IsNullOrWhiteSpace(Condition))
            {
                if (!TryPreprocessExpression(Condition, out string Processed))
                    return;

                if (!TryEvaluateExpression(Processed, out ulong Result) || Result == 0)
                    return;
            }

            PauseDebugger();
            ShowDebuggerStopContext("Breakpoint hit", Address);
        }

        public static void StepHandler(IntPtr uc, ulong Address, uint Size, IntPtr user_data)
        {
            if (TempStepTarget != 0 && Address != TempStepTarget)
                return;

            if (TempStepHookHandle != IntPtr.Zero)
                Emulator._emulator.RemoveHook(TempStepHookHandle);

            TempStepHookHandle = IntPtr.Zero;
            TempStepTarget = 0;
            PauseDebugger();
            ShowDebuggerStopContext("Stopped", Address);
        }

        public static bool TryParseAddressRange(string Input, out ulong Start, out ulong End)
        {
            Start = 0;
            End = 0;

            if (string.IsNullOrWhiteSpace(Input))
                return false;

            string[] Parts = Input.Split('-', StringSplitOptions.RemoveEmptyEntries);
            if (Parts.Length != 2)
                return false;

            if (!TryParseAddress(Parts[0], out ulong ParsedStart))
                return false;

            if (!TryParseAddress(Parts[1], out ulong ParsedEnd))
                return false;

            if (ParsedEnd < ParsedStart)
            {
                Start = ParsedEnd;
                End = ParsedStart;
            }
            else
            {
                Start = ParsedStart;
                End = ParsedEnd;
            }

            return true;
        }
        public static void ShowThreadsHelp()
        {
            PrintHighlight("[*] Thread commands:", true);
            Console.WriteLine("  threads                               List emulated threads.");
            Console.WriteLine("  threads list                          List emulated threads.");
            Console.WriteLine("  threads current                       Show the selected thread.");
            Console.WriteLine("  threads info <tid|current>            Show detailed thread information.");
            Console.WriteLine("  threads regs <tid|current>            Show saved register context for a thread.");
            Console.WriteLine("  threads switch <tid>                  Load a thread context as the selected thread.");
            Console.WriteLine("  threads suspend <tid|current|all>     Increment suspend count.");
            Console.WriteLine("  threads resume <tid|current|all>      Decrement suspend count.");
            Console.WriteLine("  threads kill <tid|current|all> [code] Mark thread(s) terminated.");
            Console.WriteLine("  threads priority <tid|current> <0-31> Set base scheduler priority.");
            Console.WriteLine("  threads rename <tid|current> <name>   Rename a thread for debugging.");
        }

        public static void ListThreads()
        {
            if (Emulator == null)
            {
                PrintHighlight("[-] Emulator is not initialized.", true);
                return;
            }

            List<EmulatedThread> Threads = Emulator.GetThreadsSnapshot();
            if (Threads.Count == 0)
            {
                PrintHighlight("[-] No emulated threads are known.", true);
                return;
            }

            PrintHighlight("[*] Threads:", true);
            Console.WriteLine("{0,-2} {1,-6} {2,-10} {3,-5} {4,-7} {5,-3} {6,-18} {7,-32} {8}", string.Empty, "TID", "State", "Susp", "Pri", "Q", "RIP", "Wait", "Name");
            foreach (EmulatedThread Thread in Threads)
            {
                RefreshThreadContext(Thread);
                string CurrentMark = Emulator.CurrentThreadId == (int)Thread.ThreadId ? "*" : " ";
                string Priority = $"{Thread.BasePriority}/{Thread.EffectivePriority}";
                string Wait = FormatThreadWaitReason(Thread);
                if (Wait.Length > 31)
                    Wait = Wait.Substring(0, 28) + "...";

                Console.WriteLine($"{CurrentMark,-2} {Thread.ThreadId,-6} {Thread.State,-10} {Thread.SuspendCount,-5} {Priority,-7} {Thread.QueueLevel,-3} 0x{GetThreadInstructionPointer(Thread):X16} {Wait,-32} {FormatThreadName(Thread)}");
            }
        }

        public static void ShowCurrentThread()
        {
            if (Emulator == null || Emulator.CurrentThreadId < 0)
            {
                PrintHighlight("[-] No current thread is selected.", true);
                return;
            }

            if (!Emulator.TryGetThread((uint)Emulator.CurrentThreadId, out EmulatedThread Thread) || Thread == null)
            {
                PrintHighlight($"[-] Current thread id {Emulator.CurrentThreadId} no longer exists.", true);
                return;
            }

            RefreshThreadContext(Thread);
            PrintHighlight($"[*] Current thread: {Thread.ThreadId} {FormatThreadName(Thread)} RIP=0x{GetThreadInstructionPointer(Thread):X}", true);
        }

        public static void ShowThreadInfo(EmulatedThread Thread)
        {
            RefreshThreadContext(Thread);
            PrintHighlight($"[*] Thread {Thread.ThreadId}: {FormatThreadName(Thread)}", true);
            Console.WriteLine($"State:             {Thread.State}");
            Console.WriteLine($"Current:           {(Emulator.CurrentThreadId == (int)Thread.ThreadId ? "yes" : "no")}");
            Console.WriteLine($"StartAddress:      0x{Thread.StartAddress:X}");
            Console.WriteLine($"Parameter:         0x{Thread.Parameter:X}");
            Console.WriteLine($"RIP:               {FormatAddressWithSymbol(GetThreadInstructionPointer(Thread))}");
            Console.WriteLine($"RSP:               0x{GetThreadStackPointer(Thread):X}");
            Console.WriteLine($"Stack:             0x{Thread.StackAddress:X}-0x{Thread.StackAddress + Thread.StackSize:X} size=0x{Thread.StackSize:X}");
            Console.WriteLine($"BasePriority:      {Thread.BasePriority}");
            Console.WriteLine($"EffectivePriority: {Thread.EffectivePriority}");
            Console.WriteLine($"DynamicBoost:      {Thread.DynamicBoost}");
            Console.WriteLine($"QueueLevel:        {Thread.QueueLevel}");
            Console.WriteLine($"AffinityMask:      0x{Thread.AffinityMask:X}");
            Console.WriteLine($"SuspendCount:      {Thread.SuspendCount}");
            Console.WriteLine($"Instructions:      {Thread.InstructionsExecuted}");
            Console.WriteLine($"ExitCode:          {Thread.ExitCode}");
            Console.WriteLine($"WaitReason:        {FormatThreadWaitReason(Thread)}");
            Console.WriteLine($"Flags:             {FormatThreadFlags(Thread)}");

            if (Thread.GuestState is LinuxThreadState LinuxState)
            {
                Console.WriteLine("Linux:");
                Console.WriteLine($"  FSBase:          0x{LinuxState.FsBase:X}");
                Console.WriteLine($"  GSBase:          0x{LinuxState.GsBase:X}");
                Console.WriteLine($"  TIDPtr:          0x{LinuxState.TIDPtr:X}");
                Console.WriteLine($"  RobustList:      0x{LinuxState.RobustListHead:X} len=0x{LinuxState.RobustListLength:X}");
                Console.WriteLine($"  Rseq:            0x{LinuxState.RseqPointer:X} len=0x{LinuxState.RseqLength:X}");
                Console.WriteLine($"  Nice:            {LinuxState.NiceValue}");
                Console.WriteLine($"  PendingSignals:  {(LinuxState.PendingSignals == null ? 0 : LinuxState.PendingSignals.Count)}");
                Console.WriteLine($"  SignalNesting:   {LinuxState.SignalNesting}");
            }
            else if (Thread.GuestState is WindowsThreadState WindowsState)
            {
                Console.WriteLine("Windows:");
                Console.WriteLine($"  TEB:             0x{WindowsState.Teb:X}");
                Console.WriteLine($"  Win32ThreadInfo: 0x{WindowsState.Win32ThreadInfo:X}");
                Console.WriteLine($"  APCs:            {(WindowsState.PendingUserApcs == null ? 0 : WindowsState.PendingUserApcs.Count)}");
                Console.WriteLine($"  Alertable:       {WindowsState.ApcAlertable}");
                Console.WriteLine($"  WaitStatus:      {WindowsState.WaitStatus}");
                Console.WriteLine($"  ExceptionDepth:  {WindowsState.ExceptionNesting}");
            }
        }

        public static void ShowThreadRegisters(EmulatedThread Thread)
        {
            RefreshThreadContext(Thread);
            CpuContext Context = Thread.Context;
            if (Context == null)
            {
                PrintHighlight("[-] Thread has no saved CPU context.", true);
                return;
            }

            if (Variables.Arch == BinaryArchitecture.x64)
            {
                Console.WriteLine($"RAX: 0x{Context.RAX:X16} RBX: 0x{Context.RBX:X16} RCX: 0x{Context.RCX:X16} RDX: 0x{Context.RDX:X16}");
                Console.WriteLine($"RSI: 0x{Context.RSI:X16} RDI: 0x{Context.RDI:X16} RBP: 0x{Context.RBP:X16} RSP: 0x{Context.RSP:X16}");
                Console.WriteLine($"R8:  0x{Context.R8:X16} R9:  0x{Context.R9:X16} R10: 0x{Context.R10:X16} R11: 0x{Context.R11:X16}");
                Console.WriteLine($"R12: 0x{Context.R12:X16} R13: 0x{Context.R13:X16} R14: 0x{Context.R14:X16} R15: 0x{Context.R15:X16}");
                Console.WriteLine($"RIP: 0x{Context.RIP:X16} RFLAGS: 0x{Context.RFLAGS:X8}");
            }
            else
            {
                Console.WriteLine($"EAX: 0x{Context.RAX:X8} EBX: 0x{Context.RBX:X8} ECX: 0x{Context.RCX:X8} EDX: 0x{Context.RDX:X8}");
                Console.WriteLine($"ESI: 0x{Context.RSI:X8} EDI: 0x{Context.RDI:X8} EBP: 0x{Context.RBP:X8} ESP: 0x{Context.RSP:X8}");
                Console.WriteLine($"EIP: 0x{Context.RIP:X8} EFLAGS: 0x{Context.RFLAGS:X8}");
            }
        }

        public static void SetAllThreadSuspendState(bool Resume)
        {
            int Changed = 0;
            foreach (EmulatedThread Thread in Emulator.GetThreadsSnapshot())
            {
                if (Thread.State == EmulatedThreadState.Terminated)
                    continue;

                bool Success = Resume
                    ? Emulator.TryResumeThread(Thread.ThreadId, out _)
                    : Emulator.TrySuspendThread(Thread.ThreadId, out _);

                if (Success)
                    Changed++;
            }

            PrintHighlight(Resume ? $"[+] Resumed {Changed} thread(s)." : $"[+] Suspended {Changed} thread(s).", true);
        }

        public static void KillAllThreads(int ExitCode)
        {
            int Changed = 0;
            foreach (EmulatedThread Thread in Emulator.GetThreadsSnapshot())
            {
                if (Emulator.TryTerminateThread(Thread.ThreadId, ExitCode))
                    Changed++;
            }

            PrintHighlight($"[+] Terminated {Changed} thread(s).", true);
        }

        public static void HandleSyscallCommand(string[] Args, string Arguments)
        {
            if (Emulator?.Syscalls == null)
            {
                PrintHighlight("[-] Syscall manager is not available.", true);
                return;
            }

            if (Args.Length == 0)
            {
                PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot(), 50, "last syscalls");
                return;
            }

            string SubCommand = Args[0].Trim().ToLowerInvariant();
            switch (SubCommand)
            {
                case "help":
                case "?":
                    ShowSyscallHelp();
                    return;

                case "list":
                case "history":
                    PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot(), ParseSyscallCount(Args, 1, 50), "syscall history");
                    return;

                case "last":
                    PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot(), ParseSyscallCount(Args, 1, 50), "last syscalls");
                    return;

                case "failed":
                case "fail":
                case "errors":
                    PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot().Where(IsSyscallFailure), ParseSyscallCount(Args, 1, 50), "failed syscalls");
                    return;

                case "tid":
                case "thread":
                    HandleSyscallTidFilter(Args);
                    return;

                case "name":
                    HandleSyscallNameFilter(Args);
                    return;

                case "number":
                case "num":
                case "nr":
                    HandleSyscallNumberFilter(Args);
                    return;

                case "rip":
                case "addr":
                case "address":
                    HandleSyscallRipFilter(Args);
                    return;

                case "contains":
                case "grep":
                case "find":
                    HandleSyscallContainsFilter(Args);
                    return;

                case "info":
                case "show":
                    HandleSyscallInfo(Args);
                    return;

                case "clear":
                    Emulator.Syscalls.ClearHistory();
                    PrintHighlight("[+] Syscall history cleared.", true);
                    return;

                case "export":
                    HandleSyscallExport(Args);
                    return;

                case "trace":
                    HandleSyscallTrace(Args);
                    return;

                case "rules":
                    ListSyscallRules();
                    return;

                case "rule":
                    HandleSyscallRule(Args);
                    return;

                default:
                    PrintHighlight("[-] Unknown syscall command. Use 'syscall help'.", true);
                    return;
            }
        }

        private static void ShowSyscallHelp()
        {
            PrintHighlight("[*] Syscall commands:", true);
            Console.WriteLine("  syscall                              Show the last 50 syscall history entries.");
            Console.WriteLine("  syscall list [count]                 Show syscall history.");
            Console.WriteLine("     History is only recorded while 'syscall trace on' is enabled.");
            Console.WriteLine("  syscall last <count>                 Show the last <count> entries.");
            Console.WriteLine("  syscall failed [count]               Show failed or unknown syscalls.");
            Console.WriteLine("  syscall tid <id> [count]             Filter by emulated thread id.");
            Console.WriteLine("  syscall name <text> [count]          Filter by syscall name.");
            Console.WriteLine("  syscall number <nr> [count]          Filter by syscall number.");
            Console.WriteLine("  syscall rip <address> [count]        Filter by syscall RIP.");
            Console.WriteLine("  syscall contains <text> [count]      Search raw syscall text.");
            Console.WriteLine("  syscall info <sequence>              Show one entry with full details.");
            Console.WriteLine("  syscall clear                        Clear recorded syscall history.");
            Console.WriteLine("  syscall export <path> [json|csv|txt] Export recorded syscall history.");
            Console.WriteLine("  syscall trace [on|off]               Toggle live syscall trace messages.");
            Console.WriteLine("  syscall rules                        List configured syscall rules.");
            Console.WriteLine("  syscall rule add <name|number> <allow|deny|modify> [options]");
            Console.WriteLine("     options: args=<count> return=<value> arg<index>=<value> interactive");
            Console.WriteLine("  syscall rule remove <id|name>        Remove a syscall rule.");
        }

        private static void PrintSyscallHistory(IEnumerable<SyscallHistoryEntry> Entries, int Count, string Title)
        {
            if (Emulator?.Syscalls?.TraceEnabled != true)
            {
                PrintHighlight("[-] Syscall history is disabled. Use 'syscall trace on' before running to collect history.", true);
                return;
            }

            SyscallHistoryEntry[] Snapshot = Entries
                .OrderBy(Entry => Entry.Sequence)
                .TakeLast(Math.Max(1, Count))
                .ToArray();

            if (Snapshot.Length == 0)
            {
                PrintHighlight("[-] No syscall history entries matched.", true);
                return;
            }

            PrintHighlight($"[*] {Title} ({Snapshot.Length} shown):", true);
            foreach (SyscallHistoryEntry Entry in Snapshot)
                Console.WriteLine(FormatSyscallHistoryEntry(Entry, false));
        }

        private static int ParseSyscallCount(string[] Args, int Index, int DefaultValue)
        {
            if (Args.Length <= Index)
                return DefaultValue;

            return int.TryParse(Args[Index], out int Count) && Count > 0 ? Count : DefaultValue;
        }

        private static void HandleSyscallTidFilter(string[] Args)
        {
            if (Args.Length < 2 || !uint.TryParse(Args[1], out uint ThreadId))
            {
                PrintHighlight("[-] Usage: syscall tid <id> [count]", true);
                return;
            }

            PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot().Where(Entry => Entry.ThreadId == ThreadId), ParseSyscallCount(Args, 2, 50), $"syscalls for tid {ThreadId}");
        }

        private static void HandleSyscallNameFilter(string[] Args)
        {
            if (Args.Length < 2)
            {
                PrintHighlight("[-] Usage: syscall name <text> [count]", true);
                return;
            }

            string Text = Args[1];
            PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot().Where(Entry => (Entry.Name ?? string.Empty).Contains(Text, StringComparison.OrdinalIgnoreCase)), ParseSyscallCount(Args, 2, 50), $"syscalls matching name '{Text}'");
        }

        private static void HandleSyscallNumberFilter(string[] Args)
        {
            if (Args.Length < 2 || !TryParseAddress(Args[1], out ulong Number, false) || Number > uint.MaxValue)
            {
                PrintHighlight("[-] Usage: syscall number <nr> [count]", true);
                return;
            }

            PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot().Where(Entry => Entry.Number == (uint)Number), ParseSyscallCount(Args, 2, 50), $"syscalls number 0x{Number:X}");
        }

        private static void HandleSyscallRipFilter(string[] Args)
        {
            if (Args.Length < 2 || !TryParseAddress(Args[1], out ulong Rip))
            {
                PrintHighlight("[-] Usage: syscall rip <address> [count]", true);
                return;
            }

            PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot().Where(Entry => Entry.Rip == Rip), ParseSyscallCount(Args, 2, 50), $"syscalls at 0x{Rip:X}");
        }

        private static void HandleSyscallContainsFilter(string[] Args)
        {
            if (Args.Length < 2)
            {
                PrintHighlight("[-] Usage: syscall contains <text> [count]", true);
                return;
            }

            int Count = 50;
            int LastIndex = Args.Length - 1;
            if (LastIndex > 1 && int.TryParse(Args[LastIndex], out int ParsedCount) && ParsedCount > 0)
            {
                Count = ParsedCount;
                LastIndex--;
            }

            string Text = string.Join(" ", Args.Skip(1).Take(LastIndex));
            PrintSyscallHistory(Emulator.Syscalls.HistorySnapshot().Where(Entry => FormatSyscallHistoryEntry(Entry, true).Contains(Text, StringComparison.OrdinalIgnoreCase)), Count, $"syscalls containing '{Text}'");
        }

        private static void HandleSyscallInfo(string[] Args)
        {
            if (Args.Length < 2 || !long.TryParse(Args[1], out long Sequence))
            {
                PrintHighlight("[-] Usage: syscall info <sequence>", true);
                return;
            }

            if (Emulator.Syscalls.TraceEnabled != true)
            {
                PrintHighlight("[-] Syscall history is disabled. Use 'syscall trace on' before running to collect history.", true);
                return;
            }

            SyscallHistoryEntry Entry = Emulator.Syscalls.HistorySnapshot().FirstOrDefault(Item => Item.Sequence == Sequence);
            if (Entry == null)
            {
                PrintHighlight("[-] Syscall history entry not found.", true);
                return;
            }

            Console.WriteLine(FormatSyscallHistoryEntry(Entry, true));
        }

        private static void HandleSyscallExport(string[] Args)
        {
            if (Args.Length < 2)
            {
                PrintHighlight("[-] Usage: syscall export <path> [json|csv|txt]", true);
                return;
            }

            if (Emulator.Syscalls.TraceEnabled != true)
            {
                PrintHighlight("[-] Syscall history is disabled. Use 'syscall trace on' before running to collect history.", true);
                return;
            }

            string PathValue = Args[1];
            string Format = Args.Length >= 3 ? Args[2].Trim().ToLowerInvariant() : System.IO.Path.GetExtension(PathValue).TrimStart('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(Format))
                Format = "txt";

            SyscallHistoryEntry[] Entries = Emulator.Syscalls.HistorySnapshot().OrderBy(Entry => Entry.Sequence).ToArray();
            string Text;
            switch (Format)
            {
                case "json":
                    Text = BuildSyscallJson(Entries);
                    break;
                case "csv":
                    Text = BuildSyscallCsv(Entries);
                    break;
                case "txt":
                case "text":
                    Text = string.Join(Environment.NewLine, Entries.Select(Entry => FormatSyscallHistoryEntry(Entry, true))) + Environment.NewLine;
                    break;
                default:
                    PrintHighlight("[-] Export format must be json, csv, or txt.", true);
                    return;
            }

            File.WriteAllText(PathValue, Text);
            PrintHighlight($"[+] Exported {Entries.Length} syscall history entries to {PathValue}.", true);
        }

        private static void HandleSyscallTrace(string[] Args)
        {
            if (Args.Length == 1)
            {
                PrintHighlight($"[*] Syscall trace is {(Emulator.Syscalls.TraceEnabled ? "enabled" : "disabled")}.", true);
                return;
            }

            string TraceValue = Args[1].ToLowerInvariant();
            if (TraceValue == "on" || TraceValue == "enable" || TraceValue == "enabled")
            {
                Emulator.Syscalls.TraceEnabled = true;
                PrintHighlight("[+] Syscall trace enabled. Syscall history will be recorded while tracing is on.", true);
            }
            else if (TraceValue == "off" || TraceValue == "disable" || TraceValue == "disabled")
            {
                Emulator.Syscalls.TraceEnabled = false;
                PrintHighlight("[+] Syscall trace disabled and recorded history cleared.", true);
            }
            else
            {
                PrintHighlight("[-] Usage: syscall trace [on|off]", true);
            }
        }

        private static void ListSyscallRules()
        {
            SyscallRule[] Rules = Emulator.Syscalls.ListRules().ToArray();
            if (Rules.Length == 0)
            {
                PrintHighlight("[-] No syscall rules configured.", true);
                return;
            }

            PrintHighlight("[*] Syscall rules:", true);
            foreach (SyscallRule Rule in Rules)
            {
                string Target = Rule.Number.HasValue ? $"0x{Rule.Number.Value:X}" : (Rule.Name ?? "unknown");
                string ReturnValue = Rule.ForcedReturn.HasValue ? $"0x{Rule.ForcedReturn.Value:X}" : "-";
                string ModifyArgs = Rule.ModifyArgs.Count > 0
                    ? string.Join(", ", Rule.ModifyArgs.Select(Kv => $"arg{Kv.Key}=0x{Kv.Value:X}"))
                    : "-";
                Console.WriteLine($"{Rule.Id} | {Target} | {Rule.Action} | args={Rule.ArgsCount} | return={ReturnValue} | interactive={Rule.Interactive} | modify={ModifyArgs}");
            }
        }

        private static void HandleSyscallRule(string[] Args)
        {
            if (Args.Length < 2)
            {
                ShowSyscallHelp();
                return;
            }

            string RuleAction = Args[1].ToLowerInvariant();
            if (RuleAction == "list")
            {
                ListSyscallRules();
                return;
            }

            if (RuleAction == "remove" || RuleAction == "rm" || RuleAction == "delete")
            {
                if (Args.Length < 3)
                {
                    PrintHighlight("[-] Usage: syscall rule remove <id|name>", true);
                    return;
                }

                if (Emulator.Syscalls.RemoveRule(Args[2]))
                    PrintHighlight("[+] Syscall rule removed.", true);
                else
                    PrintHighlight("[-] Syscall rule not found.", true);
                return;
            }

            if (RuleAction == "add")
            {
                AddSyscallRule(Args);
                return;
            }

            PrintHighlight("[-] Unknown syscall rule command.", true);
        }

        private static void AddSyscallRule(string[] Args)
        {
            if (Args.Length < 4)
            {
                PrintHighlight("[-] Usage: syscall rule add <name|number> <allow|deny|modify> [options]", true);
                return;
            }

            if (!TryParseSyscallTarget(Args[2], out uint? Number, out string Name))
            {
                PrintHighlight("[-] Invalid syscall target.", true);
                return;
            }

            if (!TryParseSyscallAction(Args[3], out SyscallAction Action))
            {
                PrintHighlight("[-] Invalid action. Use allow, deny, modify, or log.", true);
                return;
            }

            SyscallRule Rule = new SyscallRule
            {
                Number = Number,
                Name = Name,
                Action = Action
            };

            int MaxArgIndex = -1;
            for (int i = 4; i < Args.Length; i++)
            {
                string Token = Args[i];
                if (Token.StartsWith("args=", StringComparison.OrdinalIgnoreCase))
                {
                    string CountToken = Token.Substring("args=".Length);
                    if (int.TryParse(CountToken, out int Count) && Count >= 0)
                        Rule.ArgsCount = Count;
                    else
                        PrintHighlight($"[-] Invalid args count: {CountToken}", true);
                    continue;
                }

                if (Token.StartsWith("return=", StringComparison.OrdinalIgnoreCase))
                {
                    string ValueToken = Token.Substring("return=".Length);
                    if (TryParseAddress(ValueToken, out ulong RetValue))
                        Rule.ForcedReturn = RetValue;
                    else
                        PrintHighlight($"[-] Invalid return value: {ValueToken}", true);
                    continue;
                }

                if (Token.StartsWith("arg", StringComparison.OrdinalIgnoreCase) && Token.Contains('='))
                {
                    int Split = Token.IndexOf('=');
                    string IndexToken = Token.Substring(3, Split - 3);
                    string ValueToken = Token.Substring(Split + 1);
                    if (int.TryParse(IndexToken, out int ArgIndex) && TryParseAddress(ValueToken, out ulong ArgValue))
                    {
                        Rule.ModifyArgs[ArgIndex] = ArgValue;
                        if (ArgIndex > MaxArgIndex)
                            MaxArgIndex = ArgIndex;
                    }
                    else
                    {
                        PrintHighlight($"[-] Invalid arg specification: {Token}", true);
                    }
                    continue;
                }

                if (Token.Equals("interactive", StringComparison.OrdinalIgnoreCase))
                {
                    Rule.Interactive = true;
                    continue;
                }

                PrintHighlight($"[-] Unknown option: {Token}", true);
            }

            if (Rule.ArgsCount == 0 && MaxArgIndex >= 0)
                Rule.ArgsCount = MaxArgIndex + 1;

            Emulator.Syscalls.AddRule(Rule);
            PrintHighlight($"[+] Added syscall rule {Rule.Id}.", true);
        }

        private static string BuildSyscallJson(SyscallHistoryEntry[] Entries)
        {
            StringBuilder Builder = new StringBuilder();
            Builder.AppendLine("[");
            for (int i = 0; i < Entries.Length; i++)
            {
                SyscallHistoryEntry Entry = Entries[i];
                Builder.Append("  {");
                Builder.Append($"\"sequence\":{Entry.Sequence},");
                Builder.Append($"\"threadId\":{Entry.ThreadId},");
                Builder.Append($"\"guest\":\"{JsonEscape(Entry.Guest.ToString())}\",");
                Builder.Append($"\"abi\":\"{JsonEscape(Entry.Abi.ToString())}\",");
                Builder.Append($"\"rip\":\"0x{Entry.Rip:X}\",");
                Builder.Append($"\"number\":{Entry.Number},");
                Builder.Append($"\"name\":\"{JsonEscape(Entry.Name ?? string.Empty)}\",");
                Builder.Append("\"args\":[");
                for (int ArgIndex = 0; ArgIndex < (Entry.Args?.Length ?? 0); ArgIndex++)
                {
                    if (ArgIndex > 0)
                        Builder.Append(",");
                    Builder.Append($"\"0x{Entry.Args[ArgIndex]:X}\"");
                }
                Builder.Append("],");
                Builder.Append($"\"return\":\"{JsonEscape(FormatSyscallReturnValue(Entry))}\",");
                Builder.Append($"\"implemented\":{Entry.Implemented.ToString().ToLowerInvariant()},");
                Builder.Append($"\"handledByRule\":{Entry.HandledByRule.ToString().ToLowerInvariant()}");
                Builder.Append(i + 1 == Entries.Length ? "}" : "},");
                Builder.AppendLine();
            }
            Builder.AppendLine("]");
            return Builder.ToString();
        }

        private static string BuildSyscallCsv(SyscallHistoryEntry[] Entries)
        {
            StringBuilder Builder = new StringBuilder();
            Builder.AppendLine("sequence,thread_id,guest,abi,rip,number,name,args,return,implemented,handled_by_rule");
            foreach (SyscallHistoryEntry Entry in Entries)
            {
                Builder.Append(Entry.Sequence).Append(',');
                Builder.Append(Entry.ThreadId).Append(',');
                Builder.Append(CsvEscape(Entry.Guest.ToString())).Append(',');
                Builder.Append(CsvEscape(Entry.Abi.ToString())).Append(',');
                Builder.Append(CsvEscape($"0x{Entry.Rip:X}")).Append(',');
                Builder.Append(Entry.Number).Append(',');
                Builder.Append(CsvEscape(Entry.Name ?? string.Empty)).Append(',');
                Builder.Append(CsvEscape(FormatSyscallArguments(Entry))).Append(',');
                Builder.Append(CsvEscape(FormatSyscallReturnValue(Entry))).Append(',');
                Builder.Append(Entry.Implemented).Append(',');
                Builder.Append(Entry.HandledByRule).AppendLine();
            }

            return Builder.ToString();
        }

        private static string JsonEscape(string Text)
        {
            if (Text == null)
                return string.Empty;

            StringBuilder Builder = new StringBuilder(Text.Length + 8);
            foreach (char Ch in Text)
            {
                switch (Ch)
                {
                    case '\\': Builder.Append("\\\\"); break;
                    case '"': Builder.Append("\\\""); break;
                    case '\r': Builder.Append("\\r"); break;
                    case '\n': Builder.Append("\\n"); break;
                    case '\t': Builder.Append("\\t"); break;
                    default:
                        if (char.IsControl(Ch))
                            Builder.Append($"\\u{(int)Ch:X4}");
                        else
                            Builder.Append(Ch);
                        break;
                }
            }

            return Builder.ToString();
        }

        private static string CsvEscape(string Text)
        {
            Text ??= string.Empty;
            return '"' + Text.Replace("\"", "\"\"") + '"';
        }

        public static void HandleThreadsCommand(string[] Args, string Arguments)
        {
            if (Emulator == null)
            {
                PrintHighlight("[-] Emulator is not initialized.", true);
                return;
            }

            if (Args.Length == 0 || Args[0].Equals("list", StringComparison.OrdinalIgnoreCase) || Args[0].Equals("ls", StringComparison.OrdinalIgnoreCase))
            {
                ListThreads();
                return;
            }

            string Action = Args[0].ToLowerInvariant();
            switch (Action)
            {
                case "help":
                case "?":
                    ShowThreadsHelp();
                    return;

                case "current":
                case "cur":
                    ShowCurrentThread();
                    return;

                case "info":
                case "show":
                    if (!TryGetThreadArgument(Args, 1, out EmulatedThread InfoThread))
                    {
                        PrintHighlight("[-] Usage: threads info <tid|current>", true);
                        return;
                    }
                    ShowThreadInfo(InfoThread);
                    return;

                case "regs":
                case "registers":
                    if (!TryGetThreadArgument(Args, 1, out EmulatedThread RegistersThread))
                    {
                        PrintHighlight("[-] Usage: threads regs <tid|current>", true);
                        return;
                    }
                    ShowThreadRegisters(RegistersThread);
                    return;

                case "switch":
                case "select":
                case "use":
                    if (Args.Length < 2 || !TryParseThreadId(Args[1], out uint SwitchThreadId))
                    {
                        PrintHighlight("[-] Usage: threads switch <tid>", true);
                        return;
                    }

                    if (!Emulator.TrySwitchToThread(SwitchThreadId))
                    {
                        PrintHighlight($"[-] Failed to switch to thread {SwitchThreadId}.", true);
                        return;
                    }

                    PrintHighlight($"[+] Switched to thread {SwitchThreadId}.", true);
                    return;

                case "suspend":
                case "pause":
                    if (Args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: threads suspend <tid|current|all>", true);
                        return;
                    }

                    if (IsAllThreadsTarget(Args[1]))
                    {
                        SetAllThreadSuspendState(false);
                        return;
                    }

                    if (!TryParseThreadId(Args[1], out uint SuspendThreadId) || !Emulator.TrySuspendThread(SuspendThreadId, out int PreviousSuspendCount))
                    {
                        PrintHighlight("[-] Failed to suspend thread.", true);
                        return;
                    }

                    PrintHighlight($"[+] Suspended thread {SuspendThreadId}. Previous suspend count: {PreviousSuspendCount}.", true);
                    return;

                case "resume":
                case "unpause":
                    if (Args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: threads resume <tid|current|all>", true);
                        return;
                    }

                    if (IsAllThreadsTarget(Args[1]))
                    {
                        SetAllThreadSuspendState(true);
                        return;
                    }

                    if (!TryParseThreadId(Args[1], out uint ResumeThreadId) || !Emulator.TryResumeThread(ResumeThreadId, out int PreviousResumeCount))
                    {
                        PrintHighlight("[-] Failed to resume thread.", true);
                        return;
                    }

                    PrintHighlight($"[+] Resumed thread {ResumeThreadId}. Previous suspend count: {PreviousResumeCount}.", true);
                    return;

                case "kill":
                case "terminate":
                    if (Args.Length < 2)
                    {
                        PrintHighlight("[-] Usage: threads kill <tid|current|all> [exit_code]", true);
                        return;
                    }

                    int ExitCode = 0;
                    ulong ParsedExitCode = 0;
                    if (Args.Length >= 3 && (!TryParseAddress(Args[2], out ParsedExitCode, false) || ParsedExitCode > int.MaxValue))
                    {
                        PrintHighlight("[-] Invalid exit code.", true);
                        return;
                    }
                    else if (Args.Length >= 3)
                    {
                        ExitCode = (int)ParsedExitCode;
                    }

                    if (IsAllThreadsTarget(Args[1]))
                    {
                        KillAllThreads(ExitCode);
                        return;
                    }

                    if (!TryParseThreadId(Args[1], out uint KillThreadId) || !Emulator.TryTerminateThread(KillThreadId, ExitCode))
                    {
                        PrintHighlight("[-] Failed to terminate thread.", true);
                        return;
                    }

                    PrintHighlight($"[+] Terminated thread {KillThreadId} with exit code {ExitCode}.", true);
                    return;

                case "priority":
                case "pri":
                    if (!TryGetThreadArgument(Args, 1, out EmulatedThread PriorityThread) || Args.Length < 3 || !int.TryParse(Args[2], out int Priority))
                    {
                        PrintHighlight("[-] Usage: threads priority <tid|current> <0-31>", true);
                        return;
                    }

                    PriorityThread.BasePriority = Math.Clamp(Priority, 0, 31);
                    PrintHighlight($"[+] Thread {PriorityThread.ThreadId} base priority set to {PriorityThread.BasePriority}.", true);
                    return;

                case "rename":
                case "name":
                    if (!TryGetThreadArgument(Args, 1, out EmulatedThread RenameThread) || Args.Length < 3)
                    {
                        PrintHighlight("[-] Usage: threads rename <tid|current> <name>", true);
                        return;
                    }

                    int RenameIndex = Arguments.IndexOf(Args[1], StringComparison.Ordinal);
                    string NewName = RenameIndex >= 0 ? Arguments.Substring(RenameIndex + Args[1].Length).Trim() : string.Join(' ', Args.Skip(2));
                    if (string.IsNullOrWhiteSpace(NewName))
                    {
                        PrintHighlight("[-] Thread name cannot be empty.", true);
                        return;
                    }

                    RenameThread.Name = NewName;
                    PrintHighlight($"[+] Thread {RenameThread.ThreadId} renamed to {NewName}.", true);
                    return;
            }

            PrintHighlight("[-] Unknown threads command. Use: threads help", true);
        }

        public static void HandleHandlesCommand(string[] Args, string Arguments)
        {
            if (Emulator == null)
            {
                PrintHighlight("[-] Emulator is not initialized.", true);
                return;
            }

            if (Args.Length == 0)
            {
                ListHandles(null);
                return;
            }

            string Action = Args[0].ToLowerInvariant();
            switch (Action)
            {
                case "help":
                case "?":
                    ShowHandlesHelp();
                    return;

                case "list":
                case "ls":
                    ListHandles(Args.Length >= 2 ? Args[1] : null);
                    return;

                case "info":
                case "show":
                    if (!TryGetHandleArgument(Args, 1, out ulong InfoHandle))
                    {
                        PrintHighlight("[-] Usage: handles info <handle|fd>", true);
                        return;
                    }
                    ShowHandleInfo(InfoHandle);
                    return;

                case "refs":
                case "aliases":
                    if (!TryGetHandleArgument(Args, 1, out ulong RefsHandle))
                    {
                        PrintHighlight("[-] Usage: handles refs <handle|fd>", true);
                        return;
                    }
                    ListHandleReferences(RefsHandle);
                    return;

                case "inspect":
                case "dump":
                    if (!TryGetHandleArgument(Args, 1, out ulong InspectHandle))
                    {
                        PrintHighlight("[-] Usage: handles inspect <handle|fd>", true);
                        return;
                    }
                    InspectHandleObject(InspectHandle);
                    return;

                case "close":
                case "delete":
                case "del":
                    if (!TryGetHandleArgument(Args, 1, out ulong CloseHandle))
                    {
                        PrintHighlight("[-] Usage: handles close <handle|fd> [force]", true);
                        return;
                    }
                    CloseHandleEntry(CloseHandle, Args.Length >= 3 && Args[2].Equals("force", StringComparison.OrdinalIgnoreCase));
                    return;

                case "flags":
                case "flag":
                    if (Args.Length < 4 || !TryGetHandleArgument(Args, 1, out ulong FlagsHandle) || !TryParseBooleanValue(Args[3], out bool FlagEnabled))
                    {
                        PrintHighlight("[-] Usage: handles flags <handle|fd> <inherit|protect|cloexec|nonblock> <on|off>", true);
                        return;
                    }
                    SetHandleFlag(FlagsHandle, Args[2], FlagEnabled);
                    return;

                case "access":
                case "permissions":
                case "perms":
                    if (Args.Length < 3 || !TryGetHandleArgument(Args, 1, out ulong AccessHandle) || !TryParseAccessMaskValue(Args[2], out AccessMask Access))
                    {
                        PrintHighlight("[-] Usage: handles access <windows_handle> <mask|AccessMaskName[|...]>", true);
                        return;
                    }
                    SetWindowsHandleAccess(AccessHandle, Access);
                    return;

                case "target":
                case "point":
                case "retarget":
                    if (Args.Length < 3 || !TryGetHandleArgument(Args, 1, out ulong TargetHandle) || !TryParseHandleValue(Args[2], out ulong SourceHandle))
                    {
                        PrintHighlight("[-] Usage: handles target <target_handle|fd> <source_handle|fd> [copyattrs]", true);
                        return;
                    }
                    RetargetHandleEntry(TargetHandle, SourceHandle, Args.Length >= 4 && IsCopyAttributesArgument(Args[3]));
                    return;

                case "dup":
                case "duplicate":
                    if (Args.Length < 2 || !TryGetHandleArgument(Args, 1, out ulong DuplicateSource))
                    {
                        PrintHighlight("[-] Usage: handles dup <source_handle|fd> [minimum_fd] [copyattrs]", true);
                        return;
                    }
                    DuplicateHandleEntry(DuplicateSource, Args);
                    return;

                case "path":
                    if (Args.Length < 3 || !TryGetHandleArgument(Args, 1, out ulong PathHandle))
                    {
                        PrintHighlight("[-] Usage: handles path <handle|fd> <new_path>", true);
                        return;
                    }
                    SetHandlePath(PathHandle, GetTrailingHandleArgument(Arguments, Args, 2));
                    return;

                case "offset":
                case "position":
                    if (Args.Length < 3 || !TryGetHandleArgument(Args, 1, out ulong OffsetHandle) || !TryParseAddress(Args[2], out ulong Offset, false))
                    {
                        PrintHighlight("[-] Usage: handles offset <handle|fd> <offset>", true);
                        return;
                    }
                    SetHandleOffset(OffsetHandle, Offset);
                    return;

                case "setraw":
                case "rawset":
                    if (Args.Length < 4 || !TryGetHandleArgument(Args, 1, out ulong RawHandle))
                    {
                        PrintHighlight("[-] Usage: handles setraw <handle|fd> <field_or_property> <value>", true);
                        return;
                    }
                    SetRawHandleObjectField(RawHandle, Args[2], GetTrailingHandleArgument(Arguments, Args, 3));
                    return;

                case "set":
                    if (Args.Length < 4 || !TryGetHandleArgument(Args, 1, out ulong SetHandle))
                    {
                        PrintHighlight("[-] Usage: handles set <handle|fd> <field> <value>", true);
                        return;
                    }
                    SetHandleField(SetHandle, Args[2], GetTrailingHandleArgument(Arguments, Args, 3));
                    return;
            }

            PrintHighlight("[-] Unknown handles command. Use: handles help", true);
        }

        private static void ShowHandlesHelp()
        {
            Console.WriteLine("handles commands:");
            Console.WriteLine("  handles list [all|file|dir|socket|eventfd|timerfd|epoll|windows_type]");
            Console.WriteLine("  handles info <handle|fd>");
            Console.WriteLine("  handles refs <handle|fd>");
            Console.WriteLine("  handles inspect <handle|fd>");
            Console.WriteLine("  handles close <handle|fd> [force]");
            Console.WriteLine("  handles flags <handle|fd> <inherit|protect|cloexec|nonblock> <on|off>");
            Console.WriteLine("  handles access <windows_handle> <mask|AccessMaskName[|...]>");
            Console.WriteLine("  handles target <target_handle|fd> <source_handle|fd> [copyattrs]");
            Console.WriteLine("  handles dup <source_handle|fd> [minimum_fd] [copyattrs]");
            Console.WriteLine("  handles path <handle|fd> <new_path>");
            Console.WriteLine("  handles offset <handle|fd> <offset>");
            Console.WriteLine("  handles set <handle|fd> <field> <value>");
            Console.WriteLine("  handles setraw <handle|fd> <field_or_property> <value>");
            Console.WriteLine();
            Console.WriteLine("common set fields:");
            Console.WriteLine("  Windows: inherit, protect, access, target, path, offset, signaled, name, count, maximum");
            Console.WriteLine("  Linux:   cloexec, nonblock, target, path, hostpath, offset, counter");
            Console.WriteLine();
            Console.WriteLine("notes:");
            Console.WriteLine("  target changes what an existing handle/fd points to.");
            Console.WriteLine("  setraw writes a real object field/property through the menu debugger layer.");
            Console.WriteLine("  no debugger-only handle APIs are required in the emulator core.");
        }

        private static bool TryGetHandleArgument(string[] Args, int Index, out ulong Handle)
        {
            Handle = 0;
            return Args.Length > Index && TryParseHandleValue(Args[Index], out Handle);
        }

        private static void ListHandles(string Filter)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                ListLinuxDescriptors(LinuxHelper, Filter);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                ListWindowsHandles(WindowsHelper, Filter);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void ShowHandleInfo(ulong Handle)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                ShowLinuxDescriptorInfo(LinuxHelper, Handle);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                ShowWindowsHandleInfo(WindowsHelper, Handle);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void InspectHandleObject(ulong Handle)
        {
            object Object = GetHandleObjectForCurrentGuest(Handle);
            if (Object == null)
            {
                PrintHighlight("[-] Handle/fd does not exist.", true);
                return;
            }

            PrintDebuggerObjectMembers(Object);
        }

        private static void ListHandleReferences(ulong Handle)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                FileDescriptorEntry Entry = LinuxHelper.DescriptorTable.GetEntry(Handle);
                if (Entry == null)
                {
                    PrintHighlight($"[-] Linux fd {Handle} does not exist.", true);
                    return;
                }

                Console.WriteLine($"Linux fds pointing to the same object as fd {Handle}:");
                foreach (KeyValuePair<ulong, FileDescriptorEntry> Pair in GetLinuxDescriptorSnapshot(LinuxHelper.DescriptorTable))
                {
                    if (ReferenceEquals(Pair.Value.Object, Entry.Object))
                        Console.WriteLine($"  fd {Pair.Key}: cloexec={Pair.Value.CloseOnExec} flags={FormatLinuxDescriptorFlags(Pair.Value.CloseOnExec, GetLinuxStatusFlags(Pair.Value.Object))}");
                }
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                IHandleObject Object = WindowsHelper.HandleManager.GetObjectByHandle(Handle);
                if (Object == null)
                {
                    PrintHighlight($"[-] Windows handle 0x{Handle:X} does not exist.", true);
                    return;
                }

                Console.WriteLine($"Windows handles pointing to the same object as 0x{Handle:X}:");
                foreach (KeyValuePair<ulong, IHandleObject> Pair in GetWindowsHandleSnapshot(WindowsHelper))
                {
                    if (ReferenceEquals(Pair.Value, Object))
                        Console.WriteLine($"  0x{Pair.Key:X}: access={FormatWindowsAccessMask(WindowsHelper.HandleManager.GetPermissionsByHandle(Pair.Key))} flags={FormatWindowsHandleFlags(WindowsHelper.HandleManager.GetHandleFlags(Pair.Key))}");
                }
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void CloseHandleEntry(ulong Handle, bool Force)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                if (!LinuxHelper.DescriptorTable.CloseHandle(Handle))
                {
                    PrintHighlight($"[-] Linux fd {Handle} does not exist.", true);
                    return;
                }

                PrintHighlight($"[+] Closed Linux fd {Handle}.", true);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                ObjectHandleFlags Flags = WindowsHelper.HandleManager.GetHandleFlags(Handle);
                if (!Force && (Flags & ObjectHandleFlags.ProtectFromClose) != 0)
                {
                    PrintHighlight("[-] Handle is protected from close. Use: handles close <handle> force", true);
                    return;
                }

                if (!WindowsHelper.HandleManager.HandleExists(Handle))
                {
                    PrintHighlight($"[-] Windows handle 0x{Handle:X} does not exist.", true);
                    return;
                }

                WindowsHelper.CloseHandle(Handle);
                PrintHighlight($"[+] Closed Windows handle 0x{Handle:X}.", true);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void SetHandleFlag(ulong Handle, string FlagName, bool Enabled)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                SetLinuxDescriptorFlag(LinuxHelper, Handle, FlagName, Enabled);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                SetWindowsHandleFlag(WindowsHelper, Handle, FlagName, Enabled);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void RetargetHandleEntry(ulong TargetHandle, ulong SourceHandle, bool CopyAttributes)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                if (!RetargetLinuxDescriptor(LinuxHelper, TargetHandle, SourceHandle, CopyAttributes))
                {
                    PrintHighlight("[-] Failed to retarget Linux fd. Make sure both descriptors exist.", true);
                    return;
                }

                PrintHighlight($"[+] Linux fd {TargetHandle} now points to the same open object as fd {SourceHandle}.", true);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                if (!RetargetWindowsHandle(WindowsHelper, TargetHandle, SourceHandle, CopyAttributes))
                {
                    PrintHighlight("[-] Failed to retarget Windows handle. Make sure both handles exist.", true);
                    return;
                }

                PrintHighlight($"[+] Windows handle 0x{TargetHandle:X} now points to the same object as handle 0x{SourceHandle:X}.", true);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void DuplicateHandleEntry(ulong SourceHandle, string[] Args)
        {
            bool CopyAttributes = Args.Any(IsCopyAttributesArgument);

            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                FileDescriptorEntry Entry = LinuxHelper.DescriptorTable.GetEntry(SourceHandle);
                if (Entry == null)
                {
                    PrintHighlight($"[-] Linux fd {SourceHandle} does not exist.", true);
                    return;
                }

                ulong MinimumDescriptor = 0;
                if (Args.Length >= 3 && !IsCopyAttributesArgument(Args[2]) && !TryParseAddress(Args[2], out MinimumDescriptor, false))
                {
                    PrintHighlight("[-] minimum_fd is invalid.", true);
                    return;
                }

                ulong NewDescriptor = LinuxHelper.DescriptorTable.AddHandle(Entry.Object, CopyAttributes ? Entry.CloseOnExec : false, MinimumDescriptor);
                PrintHighlight($"[+] Duplicated Linux fd {SourceHandle} into fd {NewDescriptor}.", true);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                IHandleObject Object = WindowsHelper.HandleManager.GetObjectByHandle(SourceHandle);
                if (Object == null)
                {
                    PrintHighlight($"[-] Windows handle 0x{SourceHandle:X} does not exist.", true);
                    return;
                }

                AccessMask Access = WindowsHelper.HandleManager.GetPermissionsByHandle(SourceHandle);
                WinHandle NewHandle = WindowsHelper.HandleManager.AddHandle(Object, Access);
                if (CopyAttributes)
                    WindowsHelper.HandleManager.SetHandleFlags(NewHandle.Handle, WindowsHelper.HandleManager.GetHandleFlags(SourceHandle));

                WindowsHelper.WinHandles.Add(NewHandle);
                PrintHighlight($"[+] Duplicated Windows handle 0x{SourceHandle:X} into 0x{NewHandle.Handle:X}.", true);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void SetHandlePath(ulong Handle, string PathValue)
        {
            if (string.IsNullOrWhiteSpace(PathValue))
            {
                PrintHighlight("[-] Path cannot be empty.", true);
                return;
            }

            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                FileDescriptorEntry Entry = LinuxHelper.DescriptorTable.GetEntry(Handle);
                if (Entry?.Object is FileObject File)
                {
                    File.Path = PathValue;
                    PrintHighlight($"[+] Linux fd {Handle} path set to {PathValue}.", true);
                    return;
                }

                PrintHighlight("[-] Linux fd is not a file descriptor with a path.", true);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                IHandleObject Object = WindowsHelper.HandleManager.GetObjectByHandle(Handle);
                switch (Object)
                {
                    case WinFile File:
                        File.Path = PathValue;
                        RebuildWindowsHandleIndex(WindowsHelper);
                        PrintHighlight($"[+] Windows file handle 0x{Handle:X} path set to {PathValue}.", true);
                        return;
                    case WinSection Section:
                        Section.Path = PathValue;
                        RebuildWindowsHandleIndex(WindowsHelper);
                        PrintHighlight($"[+] Windows section handle 0x{Handle:X} path set to {PathValue}.", true);
                        return;
                    case WinSymbolicLink Link:
                        Link.Target = PathValue;
                        RebuildWindowsHandleIndex(WindowsHelper);
                        PrintHighlight($"[+] Windows symbolic link handle 0x{Handle:X} target set to {PathValue}.", true);
                        return;
                }

                PrintHighlight("[-] Windows handle does not expose a path/target field.", true);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void SetHandleOffset(ulong Handle, ulong Offset)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                FileDescriptorEntry Entry = LinuxHelper.DescriptorTable.GetEntry(Handle);
                if (Entry?.Object is FileObject File)
                {
                    File.Offset = Offset;
                    PrintHighlight($"[+] Linux fd {Handle} offset set to 0x{Offset:X}.", true);
                    return;
                }

                PrintHighlight("[-] Linux fd is not seekable file descriptor state.", true);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                if (WindowsHelper.HandleManager.GetObjectByHandle(Handle) is WinFile File)
                {
                    File.Position = unchecked((long)Offset);
                    PrintHighlight($"[+] Windows file handle 0x{Handle:X} position set to 0x{Offset:X}.", true);
                    return;
                }

                PrintHighlight("[-] Windows handle is not a file handle.", true);
                return;
            }

            PrintHighlight("[-] Current guest does not expose handles or file descriptors.", true);
        }

        private static void SetHandleField(ulong Handle, string FieldName, string Value)
        {
            if (string.IsNullOrWhiteSpace(FieldName))
            {
                PrintHighlight("[-] Field cannot be empty.", true);
                return;
            }

            string Normalized = FieldName.Trim().ToLowerInvariant();
            switch (Normalized)
            {
                case "target":
                case "points":
                case "pointsto":
                    if (!TryParseHandleValue(Value, out ulong SourceHandle))
                    {
                        PrintHighlight("[-] Target value must be a handle/fd number.", true);
                        return;
                    }
                    RetargetHandleEntry(Handle, SourceHandle, true);
                    return;

                case "path":
                case "targetpath":
                case "hostpath":
                    SetSpecialPathField(Handle, Normalized, Value);
                    return;

                case "offset":
                case "position":
                    if (!TryParseAddress(Value, out ulong Offset, false))
                    {
                        PrintHighlight("[-] Offset value is invalid.", true);
                        return;
                    }
                    SetHandleOffset(Handle, Offset);
                    return;

                case "cloexec":
                case "closeonexec":
                case "nonblock":
                case "nonblocking":
                case "inherit":
                case "protect":
                case "protectfromclose":
                    if (!TryParseBooleanValue(Value, out bool FlagValue))
                    {
                        PrintHighlight("[-] Flag value must be on/off.", true);
                        return;
                    }
                    SetHandleFlag(Handle, Normalized, FlagValue);
                    return;

                case "access":
                case "permissions":
                case "perms":
                    if (!TryParseAccessMaskValue(Value, out AccessMask Mask))
                    {
                        PrintHighlight("[-] Access mask value is invalid.", true);
                        return;
                    }
                    SetWindowsHandleAccess(Handle, Mask);
                    return;

                case "counter":
                    SetLinuxEventfdCounter(Handle, Value);
                    return;

                case "signaled":
                case "state":
                case "name":
                case "count":
                case "current":
                case "maximum":
                case "max":
                    SetWindowsObjectField(Handle, Normalized, Value);
                    return;
            }

            SetRawHandleObjectField(Handle, FieldName, Value);
        }

        private static void SetRawHandleObjectField(ulong Handle, string MemberName, string Value)
        {
            object Object = GetHandleObjectForCurrentGuest(Handle);
            if (Object == null)
            {
                PrintHighlight("[-] Handle/fd does not exist.", true);
                return;
            }

            if (!TrySetDebuggerMember(Object, MemberName, Value, out string ErrorMessage))
            {
                PrintHighlight($"[-] {ErrorMessage}", true);
                return;
            }

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
            {
                RebuildWindowsHandleIndex(WindowsHelper);
                SyncWindowsHandleCache(WindowsHelper, Handle);
            }

            PrintHighlight($"[+] {MemberName} set to {Value}.", true);
        }

        private static void SetSpecialPathField(ulong Handle, string FieldName, string Value)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
            {
                FileDescriptorEntry Entry = LinuxHelper.DescriptorTable.GetEntry(Handle);
                if (Entry?.Object is FileObject File)
                {
                    if (FieldName == "hostpath")
                        File.HostPath = Value;
                    else
                        File.Path = Value;
                    PrintHighlight($"[+] Linux fd {Handle} {FieldName} set to {Value}.", true);
                    return;
                }

                PrintHighlight("[-] Linux fd is not a file descriptor with a path.", true);
                return;
            }

            SetHandlePath(Handle, Value);
        }

        private static void ListLinuxDescriptors(LinuxSyscallsHelper Helper, string Filter)
        {
            List<KeyValuePair<ulong, FileDescriptorEntry>> Entries = GetLinuxDescriptorSnapshot(Helper.DescriptorTable);
            if (!string.IsNullOrWhiteSpace(Filter) && !Filter.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                Entries = Entries.Where(Pair => MatchesLinuxDescriptorFilter(Pair.Value.Object, Filter)).ToList();
            }

            if (Entries.Count == 0)
            {
                PrintHighlight("[!] No matching Linux file descriptors are open.", true);
                return;
            }

            Console.WriteLine("FD   Type       Access Flags                 Ref  Target");
            Console.WriteLine("-----------------------------------------------------------------------");
            foreach (KeyValuePair<ulong, FileDescriptorEntry> Pair in Entries)
            {
                IFileDescriptorObject Object = Pair.Value.Object;
                int StatusFlags = GetLinuxStatusFlags(Object);
                string Access = FormatLinuxAccessMode(StatusFlags);
                string Flags = FormatLinuxDescriptorFlags(Pair.Value.CloseOnExec, StatusFlags);
                Console.WriteLine($"{Pair.Key,-4} {GetLinuxDescriptorType(Object),-10} {Access,-6} {Flags,-21} {Object.RefCount,-4} {GetLinuxDescriptorTarget(Object)}");
            }
        }

        private static bool MatchesLinuxDescriptorFilter(IFileDescriptorObject Object, string Filter)
        {
            string Normalized = Filter.Trim().ToLowerInvariant();
            string Type = GetLinuxDescriptorType(Object).ToLowerInvariant();
            return Normalized == Type ||
                   Normalized == Type + "s" ||
                   Object.GetType().Name.Equals(Filter, StringComparison.OrdinalIgnoreCase);
        }

        private static void ShowLinuxDescriptorInfo(LinuxSyscallsHelper Helper, ulong Descriptor)
        {
            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry(Descriptor);
            if (Entry == null)
            {
                PrintHighlight($"[-] Linux fd {Descriptor} does not exist.", true);
                return;
            }

            IFileDescriptorObject Object = Entry.Object;
            int StatusFlags = GetLinuxStatusFlags(Object);
            Console.WriteLine($"FD:              {Descriptor}");
            Console.WriteLine($"Type:            {GetLinuxDescriptorType(Object)}");
            Console.WriteLine($"Access:          {FormatLinuxAccessMode(StatusFlags)}");
            Console.WriteLine($"Flags:           {FormatLinuxDescriptorFlags(Entry.CloseOnExec, StatusFlags)}");
            Console.WriteLine($"CloseOnExec:     {Entry.CloseOnExec}");
            Console.WriteLine($"RefCount:        {Object.RefCount}");
            Console.WriteLine($"Target:          {GetLinuxDescriptorTarget(Object)}");
            Console.WriteLine($"ObjectType:      {Object.GetType().FullName}");

            switch (Object)
            {
                case FileObject File:
                    Console.WriteLine($"Path:            {File.Path}");
                    Console.WriteLine($"HostPath:        {File.HostPath}");
                    Console.WriteLine($"Offset:          0x{File.Offset:X}");
                    Console.WriteLine($"StatusFlags:     0x{File.StatusFlags:X}");
                    Console.WriteLine($"Special:         {File.IsSpecialPath}");
                    Console.WriteLine($"Directory:       {File.IsDirectory}");
                    Console.WriteLine($"ReadOnlyMount:   {File.IsReadOnlyMount}");
                    break;
                case SocketObject Socket:
                    Console.WriteLine($"Domain/Type/Prot:{Socket.Domain}/{Socket.Type}/{Socket.Protocol}");
                    Console.WriteLine($"StatusFlags:     0x{Socket.StatusFlags:X}");
                    Console.WriteLine($"NonBlocking:     {Socket.NonBlocking}");
                    Console.WriteLine($"Listening:        {Socket.IsListening}");
                    Console.WriteLine($"ReusePort:        {Socket.ReusePortEnabled}");
                    break;
                case EventfdObject Eventfd:
                    Console.WriteLine($"Counter:         {Eventfd.Counter}");
                    Console.WriteLine($"Semaphore:       {Eventfd.Semaphore}");
                    Console.WriteLine($"NonBlocking:     {Eventfd.NonBlocking}");
                    Console.WriteLine($"StatusFlags:     0x{Eventfd.StatusFlags:X}");
                    break;
                case TimerfdObject Timerfd:
                    Timerfd.Update(LinuxEventHelpers.GetClockNanoseconds(Helper, Timerfd.ClockId));
                    Console.WriteLine($"ClockId:         {Timerfd.ClockId}");
                    Console.WriteLine($"Armed:           {Timerfd.Armed}");
                    Console.WriteLine($"Absolute:        {Timerfd.Absolute}");
                    Console.WriteLine($"IntervalNs:      {Timerfd.IntervalNanoseconds}");
                    Console.WriteLine($"RemainingNs:     {Timerfd.GetRemainingNanoseconds(LinuxEventHelpers.GetClockNanoseconds(Helper, Timerfd.ClockId))}");
                    Console.WriteLine($"PendingExp:      {Timerfd.PendingExpirations}");
                    Console.WriteLine($"NonBlocking:     {Timerfd.NonBlocking}");
                    Console.WriteLine($"StatusFlags:     0x{Timerfd.StatusFlags:X}");
                    break;
                case EpollObject Epoll:
                    Console.WriteLine($"Interests:       {Epoll.Interests.Count}");
                    foreach (KeyValuePair<ulong, EpollInterest> Interest in Epoll.Interests.OrderBy(Pair => Pair.Key))
                        Console.WriteLine($"  fd {Interest.Key}: events=0x{Interest.Value.Events:X8} data=0x{Interest.Value.Data:X} disabled={Interest.Value.Disabled}");
                    break;
            }
        }

        private static void SetLinuxDescriptorFlag(LinuxSyscallsHelper Helper, ulong Descriptor, string FlagName, bool Enabled)
        {
            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry(Descriptor);
            if (Entry == null)
            {
                PrintHighlight($"[-] Linux fd {Descriptor} does not exist.", true);
                return;
            }

            string Normalized = FlagName.Trim().ToLowerInvariant();
            switch (Normalized)
            {
                case "cloexec":
                case "closeonexec":
                    Entry.CloseOnExec = Enabled;
                    PrintHighlight($"[+] Linux fd {Descriptor} close-on-exec set {FormatOnOff(Enabled)}.", true);
                    return;

                case "nonblock":
                case "nonblocking":
                    if (!SetLinuxNonBlockingFlag(Entry.Object, Enabled))
                    {
                        PrintHighlight("[-] Linux fd type does not expose O_NONBLOCK.", true);
                        return;
                    }

                    PrintHighlight($"[+] Linux fd {Descriptor} nonblocking set {FormatOnOff(Enabled)}.", true);
                    return;
            }

            PrintHighlight("[-] Unsupported Linux fd flag. Use cloexec or nonblock.", true);
        }

        private static bool RetargetLinuxDescriptor(LinuxSyscallsHelper Helper, ulong TargetDescriptor, ulong SourceDescriptor, bool CopyDescriptorFlags)
        {
            FileDescriptorEntry TargetEntry = Helper.DescriptorTable.GetEntry(TargetDescriptor);
            FileDescriptorEntry SourceEntry = Helper.DescriptorTable.GetEntry(SourceDescriptor);
            if (TargetEntry == null || SourceEntry == null)
                return false;

            if (ReferenceEquals(TargetEntry.Object, SourceEntry.Object))
            {
                if (CopyDescriptorFlags)
                    TargetEntry.CloseOnExec = SourceEntry.CloseOnExec;
                return true;
            }

            ReleaseLinuxDescriptorObject(TargetEntry.Object);
            SourceEntry.Object.RefCount++;
            TargetEntry.Object = SourceEntry.Object;
            if (CopyDescriptorFlags)
                TargetEntry.CloseOnExec = SourceEntry.CloseOnExec;
            return true;
        }

        private static void ReleaseLinuxDescriptorObject(IFileDescriptorObject Object)
        {
            if (Object.RefCount > 0)
                Object.RefCount--;

            if (Object.RefCount == 0 && Object is IDisposable DisposableObject)
                DisposableObject.Dispose();
        }

        private static bool SetLinuxNonBlockingFlag(IFileDescriptorObject Object, bool Enabled)
        {
            const int O_NONBLOCK = 0x800;
            switch (Object)
            {
                case FileObject File:
                    File.StatusFlags = Enabled ? File.StatusFlags | O_NONBLOCK : File.StatusFlags & ~O_NONBLOCK;
                    return true;
                case SocketObject Socket:
                    Socket.StatusFlags = Enabled ? Socket.StatusFlags | O_NONBLOCK : Socket.StatusFlags & ~O_NONBLOCK;
                    Socket.NonBlocking = Enabled;
                    try
                    {
                        Socket.Handle.Blocking = !Enabled;
                    }
                    catch
                    {
                    }
                    return true;
                case EventfdObject Eventfd:
                    Eventfd.StatusFlags = Enabled ? Eventfd.StatusFlags | O_NONBLOCK : Eventfd.StatusFlags & ~O_NONBLOCK;
                    Eventfd.NonBlocking = Enabled;
                    return true;
                case TimerfdObject Timerfd:
                    Timerfd.StatusFlags = Enabled ? Timerfd.StatusFlags | O_NONBLOCK : Timerfd.StatusFlags & ~O_NONBLOCK;
                    Timerfd.NonBlocking = Enabled;
                    return true;
                case EpollObject:
                    return true;
                default:
                    return false;
            }
        }

        private static void SetLinuxEventfdCounter(ulong Descriptor, string Value)
        {
            if (!TryGetLinuxHandleHelper(out LinuxSyscallsHelper Helper))
            {
                PrintHighlight("[-] Counter is only supported for Linux eventfd descriptors.", true);
                return;
            }

            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry(Descriptor);
            if (Entry?.Object is not EventfdObject Eventfd)
            {
                PrintHighlight("[-] Linux fd is not an eventfd descriptor.", true);
                return;
            }

            if (!TryParseAddress(Value, out ulong Counter, false) || Counter == ulong.MaxValue)
            {
                PrintHighlight("[-] Invalid eventfd counter. The maximum stored value is UINT64_MAX - 1.", true);
                return;
            }

            Eventfd.Counter = Counter;
            PrintHighlight($"[+] Linux eventfd {Descriptor} counter set to {Counter}.", true);
        }

        private static int GetLinuxStatusFlags(IFileDescriptorObject Object)
        {
            return Object switch
            {
                FileObject File => File.StatusFlags,
                SocketObject Socket => Socket.StatusFlags,
                EventfdObject Eventfd => Eventfd.StatusFlags,
                TimerfdObject Timerfd => Timerfd.StatusFlags,
                EpollObject => SocketHelpers.O_RDWR,
                _ => 0
            };
        }

        private static string FormatLinuxAccessMode(int StatusFlags)
        {
            return (StatusFlags & 0x3) switch
            {
                0 => "r",
                1 => "w",
                2 => "rw",
                _ => "?"
            };
        }

        private static string GetLinuxDescriptorType(IFileDescriptorObject Object)
        {
            return Object switch
            {
                FileObject File when File.IsDirectory => "dir",
                FileObject => "file",
                SocketObject => "socket",
                EventfdObject => "eventfd",
                TimerfdObject => "timerfd",
                EpollObject => "epoll",
                _ => Object?.GetType().Name ?? "unknown"
            };
        }

        private static string GetLinuxDescriptorTarget(IFileDescriptorObject Object)
        {
            return Object switch
            {
                FileObject File => string.IsNullOrEmpty(File.Path) ? "<unnamed file>" : File.Path,
                SocketObject Socket => FormatSocketTarget(Socket),
                EventfdObject Eventfd => $"counter={Eventfd.Counter}",
                TimerfdObject Timerfd => Timerfd.Armed ? $"clock={Timerfd.ClockId} next={Timerfd.NextExpirationNanoseconds}" : $"clock={Timerfd.ClockId} disarmed",
                EpollObject Epoll => $"interests={Epoll.Interests.Count}",
                _ => Object?.ToString() ?? "<null>"
            };
        }

        private static string FormatSocketTarget(SocketObject Socket)
        {
            try
            {
                string Local = Socket.Handle.LocalEndPoint?.ToString() ?? "unbound";
                string Remote = Socket.Handle.RemoteEndPoint?.ToString() ?? "unconnected";
                return $"{Local} -> {Remote}";
            }
            catch
            {
                return "socket";
            }
        }

        private static void ListWindowsHandles(WinSysHelper Helper, string Filter)
        {
            List<KeyValuePair<ulong, IHandleObject>> Handles = GetWindowsHandleSnapshot(Helper);
            if (!string.IsNullOrWhiteSpace(Filter) && !Filter.Equals("all", StringComparison.OrdinalIgnoreCase))
                Handles = Handles.Where(Pair => MatchesWindowsHandleFilter(Pair.Value, Filter)).ToList();

            if (Handles.Count == 0)
            {
                PrintHighlight("[!] No matching Windows handles are open.", true);
                return;
            }

            Console.WriteLine("Handle      Type                  Access               Flags                Target");
            Console.WriteLine("------------------------------------------------------------------------------------------------");
            foreach (KeyValuePair<ulong, IHandleObject> Pair in Handles)
            {
                AccessMask Access = Helper.HandleManager.GetPermissionsByHandle(Pair.Key);
                ObjectHandleFlags Flags = Helper.HandleManager.GetHandleFlags(Pair.Key);
                Console.WriteLine($"0x{Pair.Key:X8}  {Pair.Value.ObjectType,-20} 0x{(uint)Access:X8}           {FormatWindowsHandleFlags(Flags),-19} {GetWindowsHandleTarget(Pair.Value)}");
            }
        }

        private static List<KeyValuePair<ulong, IHandleObject>> GetWindowsHandleSnapshot(WinSysHelper Helper)
        {
            if (TryGetWindowsHandleObjects(Helper.HandleManager, out Dictionary<ulong, IHandleObject> Objects))
                return Objects.OrderBy(Pair => Pair.Key).Select(Pair => new KeyValuePair<ulong, IHandleObject>(Pair.Key, Pair.Value)).ToList();

            return Helper.HandleManager.SnapshotHandles().OrderBy(Pair => Pair.Key).ToList();
        }

        private static bool MatchesWindowsHandleFilter(IHandleObject Object, string Filter)
        {
            string Normalized = Filter.Trim().ToLowerInvariant();
            return Object.ObjectType.ToString().Equals(Filter, StringComparison.OrdinalIgnoreCase) ||
                   Object.ObjectType.ToString().ToLowerInvariant().Contains(Normalized) ||
                   Object.GetType().Name.Equals(Filter, StringComparison.OrdinalIgnoreCase) ||
                   Object.GetType().Name.ToLowerInvariant().Contains(Normalized);
        }

        private static void ShowWindowsHandleInfo(WinSysHelper Helper, ulong Handle)
        {
            IHandleObject Object = Helper.HandleManager.GetObjectByHandle(Handle);
            if (Object == null)
            {
                PrintHighlight($"[-] Windows handle 0x{Handle:X} does not exist.", true);
                return;
            }

            AccessMask Access = Helper.HandleManager.GetPermissionsByHandle(Handle);
            ObjectHandleFlags Flags = Helper.HandleManager.GetHandleFlags(Handle);
            Console.WriteLine($"Handle:          0x{Handle:X}");
            Console.WriteLine($"Type:            {Object.ObjectType}");
            Console.WriteLine($"Access:          {FormatWindowsAccessMask(Access)}");
            Console.WriteLine($"Flags:           {FormatWindowsHandleFlags(Flags)}");
            Console.WriteLine($"ObjectId:        {Object.ObjectId}");
            Console.WriteLine($"ObjectType:      {Object.GetType().FullName}");
            Console.WriteLine($"Target:          {GetWindowsHandleTarget(Object)}");

            switch (Object)
            {
                case WinFile File:
                    Console.WriteLine($"Path:            {File.Path}");
                    Console.WriteLine($"Position:        0x{File.Position:X}");
                    Console.WriteLine($"Device:          {File.Device}");
                    Console.WriteLine($"Real:            {File.Real}");
                    Console.WriteLine($"Directory:       {File.Directory}");
                    Console.WriteLine($"DeletePending:   {File.DeletePending}");
                    Console.WriteLine($"Locks:           {File.Locks.Count}");
                    break;
                case WinEvent Event:
                    Console.WriteLine($"Name:            {Event.Name}");
                    Console.WriteLine($"Signaled:        {Event.Signaled}");
                    Console.WriteLine($"EventType:       {Event.EventType}");
                    break;
                case WinMutex Mutex:
                    Console.WriteLine($"Name:            {Mutex.Name}");
                    Console.WriteLine($"Signaled:        {Mutex.Signaled}");
                    Console.WriteLine($"OwnerThreadId:   {Mutex.OwnerThreadId}");
                    Console.WriteLine($"RecursionCount:  {Mutex.RecursionCount}");
                    Console.WriteLine($"Abandoned:       {Mutex.Abandoned}");
                    break;
                case WinSemaphore Semaphore:
                    Console.WriteLine($"Name:            {Semaphore.Name}");
                    Console.WriteLine($"CurrentCount:    {Semaphore.CurrentCount}");
                    Console.WriteLine($"MaximumCount:    {Semaphore.MaximumCount}");
                    break;
                case WinSection Section:
                    Console.WriteLine($"Name:            {Section.Name}");
                    Console.WriteLine($"Path:            {Section.Path}");
                    Console.WriteLine($"Size:            0x{Section.Size:X}");
                    Console.WriteLine($"Protection:      0x{Section.Protection:X}");
                    Console.WriteLine($"Attributes:      0x{Section.Attributes:X}");
                    Console.WriteLine($"BackingAddress:  0x{Section.BackingAddress:X}");
                    Console.WriteLine($"Image:           {Section.IsImage}");
                    break;
                case WinProcess Process:
                    Console.WriteLine($"PID:             {Process.PID}");
                    Console.WriteLine($"PPID:            {Process.PPID}");
                    Console.WriteLine($"Name:            {Process.Name}");
                    Console.WriteLine($"Path:            {Process.Path}");
                    Console.WriteLine($"User:            {Process.RunningUser}");
                    Console.WriteLine($"Critical:        {Process.Critical}");
                    break;
                case EmulatedThread Thread:
                    Console.WriteLine($"ThreadId:        {Thread.ThreadId}");
                    Console.WriteLine($"State:           {Thread.State}");
                    Console.WriteLine($"RIP:             0x{GetThreadInstructionPointer(Thread):X}");
                    Console.WriteLine($"Wait:            {FormatThreadWaitReason(Thread)}");
                    break;
                case WinTimer Timer:
                    Console.WriteLine($"Name:            {Timer.Name}");
                    Console.WriteLine($"TimerId:         {Timer.TimerId}");
                    Console.WriteLine($"Signaled:        {Timer.Signaled}");
                    Console.WriteLine($"Active:          {Timer.Active}");
                    Console.WriteLine($"DueTick:         {Timer.DueTick}");
                    Console.WriteLine($"PeriodMs:        {Timer.PeriodMilliseconds}");
                    break;
                case WinRegKey RegKey:
                    Console.WriteLine($"FullPath:        {RegKey.FullPath}");
                    Console.WriteLine($"NotifySignaled:  {RegKey.NotifySignaled}");
                    break;
                case WinPort Port:
                    Console.WriteLine($"Name:            {Port.Name}");
                    break;
                case WinIoCompletion Completion:
                    Console.WriteLine($"Name:            {Completion.Name}");
                    Console.WriteLine($"Queued:          {Completion.Entries.Count}");
                    Console.WriteLine($"Count:           {Completion.Count}");
                    break;
                case WinWorkerFactory Factory:
                    Console.WriteLine($"Name:            {Factory.Name}");
                    Console.WriteLine($"Paused:          {Factory.Paused}");
                    Console.WriteLine($"Shutdown:        {Factory.Shutdown}");
                    Console.WriteLine($"Workers:         {Factory.WorkerThreads.Count}");
                    Console.WriteLine($"StartRoutine:    0x{Factory.StartRoutine:X}");
                    break;
                case WinSymbolicLink Link:
                    Console.WriteLine($"FullName:        {Link.FullName}");
                    Console.WriteLine($"Target:          {Link.Target}");
                    break;
            }
        }

        private static void SetWindowsHandleFlag(WinSysHelper Helper, ulong Handle, string FlagName, bool Enabled)
        {
            if (!Helper.HandleManager.HandleExists(Handle))
            {
                PrintHighlight($"[-] Windows handle 0x{Handle:X} does not exist.", true);
                return;
            }

            ObjectHandleFlags Flags = Helper.HandleManager.GetHandleFlags(Handle);
            string Normalized = FlagName.Trim().ToLowerInvariant();
            switch (Normalized)
            {
                case "inherit":
                case "inheritable":
                    Flags = Enabled ? Flags | ObjectHandleFlags.Inherit : Flags & ~ObjectHandleFlags.Inherit;
                    break;
                case "protect":
                case "protectfromclose":
                    Flags = Enabled ? Flags | ObjectHandleFlags.ProtectFromClose : Flags & ~ObjectHandleFlags.ProtectFromClose;
                    break;
                default:
                    PrintHighlight("[-] Unsupported Windows handle flag. Use inherit or protect.", true);
                    return;
            }

            Helper.HandleManager.SetHandleFlags(Handle, Flags);
            PrintHighlight($"[+] Windows handle 0x{Handle:X} {Normalized} set {FormatOnOff(Enabled)}.", true);
        }

        private static void SetWindowsHandleAccess(ulong Handle, AccessMask Access)
        {
            if (!TryGetWindowsHandleHelper(out WinSysHelper Helper))
            {
                PrintHighlight("[-] Access masks are only supported for Windows handles.", true);
                return;
            }

            if (!TryGetWindowsHandlePermissions(Helper.HandleManager, out Dictionary<ulong, AccessMask> Permissions) || !Helper.HandleManager.HandleExists(Handle))
            {
                PrintHighlight($"[-] Windows handle 0x{Handle:X} does not exist or permissions are unavailable.", true);
                return;
            }

            Permissions[Handle] = Access;
            SyncWindowsHandleCache(Helper, Handle);
            PrintHighlight($"[+] Windows handle 0x{Handle:X} access set to {FormatWindowsAccessMask(Access)}.", true);
        }

        private static bool RetargetWindowsHandle(WinSysHelper Helper, ulong TargetHandle, ulong SourceHandle, bool CopyMetadata)
        {
            if (!TryGetWindowsHandleObjects(Helper.HandleManager, out Dictionary<ulong, IHandleObject> Objects))
                return false;
            if (!Objects.TryGetValue(TargetHandle, out IHandleObject TargetObject))
                return false;
            if (!Objects.TryGetValue(SourceHandle, out IHandleObject SourceObject))
                return false;

            if (!ReferenceEquals(TargetObject, SourceObject))
            {
                Objects[TargetHandle] = SourceObject;
                RebuildWindowsHandleIndex(Helper);
            }

            if (CopyMetadata)
            {
                if (TryGetWindowsHandlePermissions(Helper.HandleManager, out Dictionary<ulong, AccessMask> Permissions))
                    Permissions[TargetHandle] = Helper.HandleManager.GetPermissionsByHandle(SourceHandle);
                if (TryGetWindowsHandleFlags(Helper.HandleManager, out Dictionary<ulong, ObjectHandleFlags> Flags))
                    Flags[TargetHandle] = Helper.HandleManager.GetHandleFlags(SourceHandle);
            }

            SyncWindowsHandleCache(Helper, TargetHandle);
            return true;
        }

        private static void RebuildWindowsHandleIndex(WinSysHelper Helper)
        {
            if (!TryGetWindowsHandleObjects(Helper.HandleManager, out Dictionary<ulong, IHandleObject> Objects))
                return;
            if (!TryGetWindowsObjectIndex(Helper.HandleManager, out Dictionary<string, List<ulong>> ObjectIndex))
                return;

            ObjectIndex.Clear();
            foreach (KeyValuePair<ulong, IHandleObject> Pair in Objects)
            {
                if (!ObjectIndex.TryGetValue(Pair.Value.ObjectId, out List<ulong> Handles))
                {
                    Handles = new List<ulong>();
                    ObjectIndex[Pair.Value.ObjectId] = Handles;
                }

                Handles.Add(Pair.Key);
            }
        }

        private static void SetWindowsObjectField(ulong Handle, string FieldName, string Value)
        {
            if (!TryGetWindowsHandleHelper(out WinSysHelper Helper))
            {
                PrintHighlight("[-] Field is only supported for Windows handles.", true);
                return;
            }

            IHandleObject Object = Helper.HandleManager.GetObjectByHandle(Handle);
            if (Object == null)
            {
                PrintHighlight($"[-] Windows handle 0x{Handle:X} does not exist.", true);
                return;
            }

            switch (FieldName)
            {
                case "name":
                    if (SetWindowsObjectName(Object, Value))
                    {
                        RebuildWindowsHandleIndex(Helper);
                        SyncWindowsHandleCache(Helper, Handle);
                        PrintHighlight($"[+] Windows handle 0x{Handle:X} object name set to {Value}.", true);
                        return;
                    }
                    break;

                case "signaled":
                case "state":
                    if (!TryParseBooleanValue(Value, out bool Signaled))
                    {
                        PrintHighlight("[-] Signaled/state value must be on/off.", true);
                        return;
                    }
                    if (SetWindowsSignalState(Object, Signaled))
                    {
                        PrintHighlight($"[+] Windows handle 0x{Handle:X} signaled state set {FormatOnOff(Signaled)}.", true);
                        return;
                    }
                    break;

                case "count":
                case "current":
                    if (!int.TryParse(Value, out int CurrentCount))
                    {
                        PrintHighlight("[-] Count value is invalid.", true);
                        return;
                    }
                    if (Object is WinSemaphore Semaphore)
                    {
                        Semaphore.CurrentCount = Math.Clamp(CurrentCount, 0, Semaphore.MaximumCount);
                        PrintHighlight($"[+] Semaphore handle 0x{Handle:X} current count set to {Semaphore.CurrentCount}.", true);
                        return;
                    }
                    break;

                case "maximum":
                case "max":
                    if (!int.TryParse(Value, out int MaximumCount) || MaximumCount < 0)
                    {
                        PrintHighlight("[-] Maximum value is invalid.", true);
                        return;
                    }
                    if (Object is WinSemaphore Sem)
                    {
                        Sem.MaximumCount = MaximumCount;
                        if (Sem.CurrentCount > Sem.MaximumCount)
                            Sem.CurrentCount = Sem.MaximumCount;
                        PrintHighlight($"[+] Semaphore handle 0x{Handle:X} maximum count set to {Sem.MaximumCount}.", true);
                        return;
                    }
                    break;
            }

            PrintHighlight("[-] Unsupported field for this Windows handle type.", true);
        }

        private static bool SetWindowsObjectName(IHandleObject Object, string Value)
        {
            switch (Object)
            {
                case WinEvent Event:
                    Event.Name = Value;
                    return true;
                case WinMutex Mutex:
                    Mutex.Name = Value;
                    return true;
                case WinSemaphore Semaphore:
                    Semaphore.Name = Value;
                    return true;
                case WinSection Section:
                    Section.Name = Value;
                    return true;
                case WinTimer Timer:
                    Timer.Name = Value;
                    return true;
                case WinPort Port:
                    Port.Name = Value;
                    return true;
                case WinWorkerFactory Factory:
                    Factory.Name = Value;
                    return true;
                case WinIoCompletion Completion:
                    Completion.Name = Value;
                    return true;
                case WinSymbolicLink Link:
                    Link.FullName = Value;
                    return true;
                case WinProcess Process:
                    Process.Name = Value;
                    return true;
                case WinWindow Window:
                    Window.Title = Value;
                    return true;
                default:
                    return false;
            }
        }

        private static bool SetWindowsSignalState(IHandleObject Object, bool Signaled)
        {
            switch (Object)
            {
                case WinEvent Event:
                    Event.Signaled = Signaled;
                    return true;
                case WinMutex Mutex:
                    Mutex.Signaled = Signaled;
                    if (Signaled)
                    {
                        Mutex.OwnerThreadId = 0;
                        Mutex.RecursionCount = 0;
                    }
                    return true;
                case WinTimer Timer:
                    Timer.Signaled = Signaled;
                    return true;
                case WinRegKey RegKey:
                    RegKey.NotifySignaled = Signaled;
                    return true;
                default:
                    return false;
            }
        }

        private static string GetWindowsHandleTarget(IHandleObject Object)
        {
            return Object switch
            {
                WinFile File => string.IsNullOrEmpty(File.Path) ? File.ObjectId : File.Path,
                WinRegKey Key => Key.FullPath,
                WinEvent Event => $"{Event.Name} signaled={Event.Signaled}",
                WinMutex Mutex => $"{Mutex.Name} owner={Mutex.OwnerThreadId} recursion={Mutex.RecursionCount}",
                WinSemaphore Semaphore => $"{Semaphore.Name} count={Semaphore.CurrentCount}/{Semaphore.MaximumCount}",
                WinSection Section => string.IsNullOrEmpty(Section.Path) ? $"{Section.Name} size=0x{Section.Size:X}" : Section.Path,
                WinProcess Process => $"pid={Process.PID} {Process.Name}",
                EmulatedThread Thread => $"tid={Thread.ThreadId} state={Thread.State}",
                WinTimer Timer => $"{Timer.Name} active={Timer.Active} signaled={Timer.Signaled}",
                WinPort Port => Port.Name,
                WinIoCompletion Completion => $"{Completion.Name} queued={Completion.Entries.Count}",
                WinWorkerFactory Factory => $"{Factory.Name} workers={Factory.WorkerThreads.Count}",
                WinWaitCompletionPacket Packet => $"{Packet.Name} associated={Packet.Associated}",
                WinEtwRegistration Etw => Etw.ObjectId,
                WinWindow Window => $"hwnd=0x{Window.Hwnd:X} title={Window.Title}",
                WinSymbolicLink Link => $"{Link.FullName} -> {Link.Target}",
                _ => Object?.ObjectId ?? "<null>"
            };
        }

        private static object GetHandleObjectForCurrentGuest(ulong Handle)
        {
            if (TryGetLinuxHandleHelper(out LinuxSyscallsHelper LinuxHelper))
                return LinuxHelper.DescriptorTable.GetEntry(Handle)?.Object;

            if (TryGetWindowsHandleHelper(out WinSysHelper WindowsHelper))
                return WindowsHelper.HandleManager.GetObjectByHandle(Handle);

            return null;
        }

        private static bool TryGetLinuxHandleHelper(out LinuxSyscallsHelper Helper)
        {
            Helper = null;
            if (Emulator?.Guest is LinuxGuest LinuxGuest)
                Helper = LinuxGuest.Helper;

            return Helper != null;
        }

        private static bool TryGetWindowsHandleHelper(out WinSysHelper Helper)
        {
            Helper = Emulator?.WinHelper;
            return Helper != null && Emulator?.Guest is WindowsGuest;
        }

        private static bool IsCopyAttributesArgument(string Value)
        {
            return Value.Equals("copyattrs", StringComparison.OrdinalIgnoreCase) ||
                   Value.Equals("copyflags", StringComparison.OrdinalIgnoreCase) ||
                   Value.Equals("copy", StringComparison.OrdinalIgnoreCase);
        }

        private static string GetTrailingHandleArgument(string Arguments, string[] Args, int ArgIndex)
        {
            if (Args.Length <= ArgIndex)
                return string.Empty;

            int Offset = 0;
            for (int i = 0; i < ArgIndex; i++)
            {
                int Found = Arguments.IndexOf(Args[i], Offset, StringComparison.Ordinal);
                if (Found < 0)
                    return string.Join(' ', Args.Skip(ArgIndex));

                Offset = Found + Args[i].Length;
            }

            int ValueStart = Arguments.IndexOf(Args[ArgIndex], Offset, StringComparison.Ordinal);
            if (ValueStart < 0)
                return string.Join(' ', Args.Skip(ArgIndex));

            return Arguments.Substring(ValueStart).Trim();
        }

        private static void SyncWindowsHandleCache(WinSysHelper Helper, ulong Handle)
        {
            IHandleObject Object = Helper.HandleManager.GetObjectByHandle(Handle);
            if (Object == null)
                return;

            WinHandle Cached = Helper.WinHandles.FirstOrDefault(Item => Item.Handle == Handle);
            if (Cached == null)
            {
                Cached = new WinHandle { Handle = Handle };
                Helper.WinHandles.Add(Cached);
            }

            Cached.HandleType = Object.ObjectType;
            Cached.Permissions = Helper.HandleManager.GetPermissionsByHandle(Handle);
        }

    }
}