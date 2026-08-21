using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Brovan.Analysis;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.EmulationMenu;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Android
{
    /// <summary>
    /// Answers the app's debugger views
    /// </summary>
    internal static class AndroidDebugQuery
    {
        private const char TokenSeparator = '\u001E';
        private const int MaxRows = 4096;

        private static bool Stopped => !Variables.GuestExecuting;

        public static string Run(string request)
        {
            if (string.IsNullOrWhiteSpace(request))
                return string.Empty;

            string[] parts = request.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            StringBuilder text = new StringBuilder();

            try
            {
                switch (parts[0].ToLowerInvariant())
                {
                    case "state": WriteState(text); break;
                    case "regs": WriteRegisters(text, Argument(parts, 1)); break;
                    case "disasm": WriteDisassembly(text, Argument(parts, 1), Argument(parts, 2)); break;
                    case "threads": WriteThreads(text); break;
                    case "modules": WriteModules(text); break;
                    case "bp": WriteBreakpoints(text); break;
                    case "stack": WriteCallStack(text, Argument(parts, 1), Argument(parts, 2)); break;
                    case "mem": WriteMemory(text, Argument(parts, 1), Argument(parts, 2)); break;
                    case "regions": WriteRegions(text); break;
                    case "resolve": WriteResolvedAddress(text, Argument(parts, 1)); break;
                }
            }
            catch (Exception exception)
            {
                // The guest owns this state from its own threads, so a torn read is expected while it runs.
                AndroidLog.Write(AndroidNative.LogWarn, $"[brovan] Debug query '{request}' failed: {exception.Message}");
            }

            return text.ToString();
        }

        private static void WriteState(StringBuilder text)
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
            {
                text.Append("idle|0|0||?|0|0|0|0\n");
                return;
            }

            List<EmulatedThread> threads = emulator.GetThreadsSnapshot();
            ulong instructions = 0;
            int live = 0;
            foreach (EmulatedThread thread in threads)
            {
                instructions += thread.InstructionsExecuted;
                if (thread.State != EmulatedThreadState.Terminated)
                    live++;
            }

            ulong ip = CurrentInstructionPointer();
            text.Append(Stopped ? "paused" : "running").Append('|')
                .Append(emulator.CurrentThreadId).Append('|')
                .Append(Hex(ip)).Append('|')
                .Append(Clean(Symbol(ip))).Append('|')
                .Append(Variables.Arch == BinaryArchitecture.x64 ? "x64" : "x86").Append('|')
                .Append(live).Append('|')
                .Append(ModuleCount()).Append('|')
                .Append(Variables.Breakpoints.Count).Append('|')
                .Append(instructions).Append('\n');
        }

        private static void WriteRegisters(StringBuilder text, string threadArgument)
        {
            if (!TryGetThread(threadArgument, out EmulatedThread thread))
                return;

            RefreshContext(thread);
            CpuContext context = thread.Context;
            if (context == null)
                return;

            bool wide = Variables.Arch == BinaryArchitecture.x64;
            if (wide)
            {
                Register(text, "gpr", "RAX", context.RAX);
                Register(text, "gpr", "RBX", context.RBX);
                Register(text, "gpr", "RCX", context.RCX);
                Register(text, "gpr", "RDX", context.RDX);
                Register(text, "gpr", "RSI", context.RSI);
                Register(text, "gpr", "RDI", context.RDI);
                Register(text, "gpr", "RBP", context.RBP);
                Register(text, "gpr", "RSP", context.RSP);
                Register(text, "gpr", "R8", context.R8);
                Register(text, "gpr", "R9", context.R9);
                Register(text, "gpr", "R10", context.R10);
                Register(text, "gpr", "R11", context.R11);
                Register(text, "gpr", "R12", context.R12);
                Register(text, "gpr", "R13", context.R13);
                Register(text, "gpr", "R14", context.R14);
                Register(text, "gpr", "R15", context.R15);
                Register(text, "gpr", "RIP", context.RIP, Symbol(context.RIP));
            }
            else
            {
                Register(text, "gpr", "EAX", context.RAX);
                Register(text, "gpr", "EBX", context.RBX);
                Register(text, "gpr", "ECX", context.RCX);
                Register(text, "gpr", "EDX", context.RDX);
                Register(text, "gpr", "ESI", context.RSI);
                Register(text, "gpr", "EDI", context.RDI);
                Register(text, "gpr", "EBP", context.RBP);
                Register(text, "gpr", "ESP", context.RSP);
                Register(text, "gpr", "EIP", context.RIP, Symbol(context.RIP));
            }

            Register(text, "flags", wide ? "RFLAGS" : "EFLAGS", context.RFLAGS, FormatFlags(context.RFLAGS));
            Register(text, "control", "MXCSR", context.MXCSR);
            Register(text, "control", "FPCW", context.FPCW);

            Register(text, "segment", "CS", context.CS);
            Register(text, "segment", "SS", context.SS);
            Register(text, "segment", "DS", context.DS);
            Register(text, "segment", "ES", context.ES);
            Register(text, "segment", "FS", context.FS);
            Register(text, "segment", "GS", context.GS);

            int vectorRegisters = wide ? 16 : 8;
            for (int i = 0; i < vectorRegisters; i++)
            {
                text.Append("vector|XMM").Append(i).Append('|')
                    .Append(context.Xmm[(i * 2) + 1].ToString("X16")).Append(context.Xmm[i * 2].ToString("X16"))
                    .Append("|\n");
            }
        }

        private static void WriteDisassembly(StringBuilder text, string addressArgument, string countArgument)
        {
            if (!Stopped || !TryResolveAddress(addressArgument, out ulong address))
                return;

            int count = ParseCount(countArgument, 48);
            ulong cursor = address;

            // The shared decoder reads a bounded window, so a screenful is walked in blocks.
            while (count > 0)
            {
                int block = Math.Min(count, 12);
                if (!Helpers.TryDecodeInstructionBlock(cursor, block, out X86Instruction[] instructions) || instructions.Length == 0)
                    return;

                foreach (X86Instruction instruction in instructions)
                {
                    AsmLine line = AsmConsoleFormatter.FormatInstruction(instruction, false, true);
                    text.Append(Hex(instruction.Address)).Append('|')
                        .Append(FormatBytes(instruction)).Append('|')
                        .Append(line.Mnemonic).Append('|');

                    foreach (AsmToken token in line.OperandTokens)
                        text.Append((int)token.Kind).Append(Clean(token.Text)).Append(TokenSeparator);

                    text.Append('\n');
                    cursor = instruction.Address + instruction.BytesLength;
                }

                count -= instructions.Length;
            }
        }

        private static void WriteThreads(StringBuilder text)
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return;

            foreach (EmulatedThread thread in emulator.GetThreadsSnapshot())
            {
                RefreshContext(thread);
                text.Append(thread.ThreadId).Append('|')
                    .Append(thread.State).Append('|')
                    .Append(emulator.CurrentThreadId == (int)thread.ThreadId ? 1 : 0).Append('|')
                    .Append(Hex(Helpers.GetThreadInstructionPointer(thread))).Append('|')
                    .Append(Hex(Helpers.GetThreadStackPointer(thread))).Append('|')
                    .Append(thread.SuspendCount).Append('|')
                    .Append(thread.BasePriority).Append('/').Append(thread.EffectivePriority).Append('|')
                    .Append(thread.InstructionsExecuted).Append('|')
                    .Append(Clean(Helpers.FormatThreadWaitReason(thread))).Append('|')
                    .Append(Clean(Helpers.FormatThreadName(thread))).Append('\n');
            }
        }

        private static void WriteModules(StringBuilder text)
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return;

            if (Variables.Binary?.FileFormat == BinaryFormat.ELF)
            {
                if (emulator.Guest is not LinuxGuest linux)
                    return;

                foreach (LinuxLoadedModule module in linux.LoadedModules.OrderBy(Module => Module.MappedBase))
                {
                    text.Append(Clean(module.Name)).Append('|')
                        .Append(Hex(module.MappedBase)).Append('|')
                        .Append(Hex(module.Size)).Append('|')
                        .Append(Hex(module.EntryPoint)).Append('|')
                        .Append(Clean(module.Path)).Append('\n');
                }

                return;
            }

            WinSysHelper helper = emulator.WinHelper;
            if (helper == null)
                return;

            foreach (WinModule module in helper.WinModules.ToArray().OrderBy(Module => Module.MappedBase))
            {
                text.Append(Clean(module.Name)).Append('|')
                    .Append(Hex(module.MappedBase)).Append('|')
                    .Append(Hex(module.SizeOfImage)).Append('|')
                    .Append(Hex(module.EntryPoint)).Append('|')
                    .Append(Clean(module.Path)).Append('\n');
            }
        }

        private static void WriteBreakpoints(StringBuilder text)
        {
            foreach (ulong address in Variables.Breakpoints.OrderBy(Address => Address))
            {
                Variables.ConditionalBreakpoints.TryGetValue(address, out string condition);
                text.Append("bp|").Append(Hex(address)).Append('|')
                    .Append(Clean(Symbol(address))).Append('|')
                    .Append(Clean(condition)).Append('\n');
            }

            foreach (MemoryWatchpoint watchpoint in Variables.Watchpoints.Values.OrderBy(Value => Value.Id))
            {
                text.Append("wp|").Append(watchpoint.Id).Append('|')
                    .Append(Hex(watchpoint.Address)).Append('|')
                    .Append(Hex(watchpoint.Size)).Append('|')
                    .Append(Helpers.FormatWatchType(watchpoint.Type)).Append('\n');
            }
        }

        private static void WriteCallStack(StringBuilder text, string threadArgument, string countArgument)
        {
            if (!TryGetThread(threadArgument, out EmulatedThread thread))
                return;

            int maxFrames = ParseCount(countArgument, 32);

            if (Variables.CallTraceStacks.TryGetValue(thread.ThreadId, out List<CallTraceFrame> frames) && frames.Count > 0)
            {
                int start = Math.Max(0, frames.Count - maxFrames);
                for (int i = frames.Count - 1, number = 0; i >= start; i--, number++)
                {
                    CallTraceFrame frame = frames[i];
                    text.Append(number).Append('|')
                        .Append(Hex(frame.TargetAddress)).Append('|')
                        .Append(Clean(frame.TargetSymbol)).Append('|')
                        .Append(Hex(frame.StackPointer)).Append("|frame\n");
                }

                return;
            }

            if (!Stopped)
                return;

            // Without a call trace the stack is scanned for return-address candidates, the same fallback the
            // console call stack uses.
            RefreshContext(thread);
            ulong stackPointer = Helpers.GetThreadStackPointer(thread);
            uint pointerSize = Variables.Arch == BinaryArchitecture.x64 ? 8u : 4u;

            for (int i = 0, number = 0; i < maxFrames * 8 && number < maxFrames; i++)
            {
                ulong slot = stackPointer + ((ulong)i * pointerSize);
                ulong value = ReadPointer(slot, pointerSize);
                if (value == 0 || Handlers.FindModuleByAddress(value) == null)
                    continue;

                text.Append(number++).Append('|')
                    .Append(Hex(value)).Append('|')
                    .Append(Clean(Symbol(value))).Append('|')
                    .Append(Hex(slot)).Append("|raw\n");
            }
        }

        private static void WriteMemory(StringBuilder text, string addressArgument, string lengthArgument)
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null || !Stopped || !TryResolveAddress(addressArgument, out ulong address))
                return;

            const int Width = 16;
            int length = Math.Clamp(ParseCount(lengthArgument, 256), Width, 4096);

            for (int offset = 0; offset < length; offset += Width)
            {
                ulong lineAddress = address + (ulong)offset;
                if (!emulator.IsRegionMapped(lineAddress, Width))
                    return;

                byte[] data = emulator.ReadMemory(lineAddress, Width);
                text.Append(Hex(lineAddress)).Append('|').Append(Convert.ToHexString(data)).Append('\n');
            }
        }

        private static void WriteRegions(StringBuilder text)
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return;

            int rows = 0;
            foreach (MemoryRegion region in Helpers.GetMappedRegions())
            {
                if (++rows > MaxRows)
                    return;

                WinModule module = Handlers.FindModuleByAddress(region.BaseAddress);
                text.Append(Hex(region.BaseAddress)).Append('|')
                    .Append(Hex(region.Size)).Append('|')
                    .Append(region.Protections).Append('|')
                    .Append(Clean(module?.Name)).Append('\n');
            }
        }

        private static void WriteResolvedAddress(StringBuilder text, string expression)
        {
            if (TryResolveAddress(expression, out ulong address))
                text.Append(Hex(address)).Append('\n');
        }

        private static void Register(StringBuilder text, string group, string name, ulong value, string annotation = null)
        {
            text.Append(group).Append('|').Append(name).Append('|')
                .Append(Variables.Arch == BinaryArchitecture.x64 ? value.ToString("X16") : value.ToString("X8")).Append('|')
                .Append(Clean(annotation)).Append('\n');
        }

        private static bool TryGetThread(string argument, out EmulatedThread thread)
        {
            thread = null;
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return false;

            if (string.IsNullOrEmpty(argument) || argument == ".")
                return emulator.CurrentThreadId >= 0 && emulator.TryGetThread((uint)emulator.CurrentThreadId, out thread) && thread != null;

            return uint.TryParse(argument, out uint threadId) && emulator.TryGetThread(threadId, out thread) && thread != null;
        }

        private static bool TryResolveAddress(string argument, out ulong address)
        {
            address = 0;

            if (string.IsNullOrEmpty(argument) || argument == ".")
            {
                address = CurrentInstructionPointer();
                return address != 0;
            }

            return Helpers.TryParseAddress(argument, out address);
        }

        private static ulong CurrentInstructionPointer()
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return 0;

            if (emulator.CurrentThreadId >= 0 && emulator.TryGetThread((uint)emulator.CurrentThreadId, out EmulatedThread thread) && thread != null)
            {
                RefreshContext(thread);
                return Helpers.GetThreadInstructionPointer(thread);
            }

            return Stopped ? emulator.ReadRegister(emulator.IPRegister) : 0;
        }

        private static void RefreshContext(EmulatedThread thread)
        {
            if (Stopped)
                Helpers.RefreshThreadContext(thread);
        }

        private static ulong ReadPointer(ulong address, uint size)
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null || address == 0 || !emulator.IsRegionMapped(address, size))
                return 0;

            byte[] data = emulator.ReadMemory(address, size);
            return size == 8 ? BitConverter.ToUInt64(data) : BitConverter.ToUInt32(data);
        }

        private static int ModuleCount()
        {
            BinaryEmulator emulator = Variables.Emulator;
            if (emulator == null)
                return 0;

            if (emulator.Guest is LinuxGuest linux)
                return linux.LoadedModules.Count;

            return emulator.WinHelper?.WinModules?.Count ?? 0;
        }

        private static string Symbol(ulong address)
        {
            return address == 0 ? string.Empty : Handlers.FormatAddressWithSymbol(address);
        }

        private static string FormatBytes(X86Instruction instruction)
        {
            ReadOnlySpan<byte> bytes = instruction.Bytes.Span;
            int length = Math.Min((int)instruction.BytesLength, bytes.Length);
            return length <= 0 ? string.Empty : Convert.ToHexString(bytes[..length]);
        }

        private static string FormatFlags(ulong flags)
        {
            StringBuilder text = new StringBuilder();
            AppendFlag(text, flags, 0, "CF");
            AppendFlag(text, flags, 2, "PF");
            AppendFlag(text, flags, 4, "AF");
            AppendFlag(text, flags, 6, "ZF");
            AppendFlag(text, flags, 7, "SF");
            AppendFlag(text, flags, 8, "TF");
            AppendFlag(text, flags, 9, "IF");
            AppendFlag(text, flags, 10, "DF");
            AppendFlag(text, flags, 11, "OF");
            return text.ToString();
        }

        private static void AppendFlag(StringBuilder text, ulong flags, int bit, string name)
        {
            if ((flags & (1UL << bit)) == 0)
                return;

            if (text.Length != 0)
                text.Append(' ');

            text.Append(name);
        }

        private static int ParseCount(string argument, int fallback)
        {
            return int.TryParse(argument, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) && value > 0
                ? Math.Min(value, MaxRows)
                : fallback;
        }

        private static string Argument(string[] parts, int index)
        {
            return index < parts.Length ? parts[index] : string.Empty;
        }

        private static string Hex(ulong value) => value.ToString("X");

        private static string Clean(string value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            return value.Replace('|', ' ').Replace('\n', ' ').Replace(TokenSeparator, ' ');
        }
    }
}
