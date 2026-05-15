using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation.OS.Windows;
using static Brovan.Core.Helpers.BinaryHelpers;
using static Brovan.Core.Helpers.Utils;
using static Brovan.Helpers;
using static Brovan.Variables;

namespace Brovan
{
    public partial class Handlers
    {
        private static uint GetCurrentTraceThreadId()
        {
            if (Emulator == null)
                return 0;

            return Emulator.CurrentThreadId >= 0 ? (uint)Emulator.CurrentThreadId : 0;
        }

        private static ulong ReadPointerSizedStackValue(ulong Address)
        {
            ulong PointerSize = Variables.Arch == BinaryArchitecture.x64 ? 8UL : 4UL;
            if (Address == 0 || !Emulator.IsRegionMapped(Address, PointerSize))
                return 0;

            return Variables.Arch == BinaryArchitecture.x64
                ? Emulator.ReadMemoryULong(Address)
                : Emulator.ReadMemoryUInt(Address);
        }

        private static ulong ReadX64RegisterByIndex(int RegisterIndex)
        {
            return RegisterIndex switch
            {
                0 => Emulator.ReadRegister(Registers.UC_X86_REG_RAX),
                1 => Emulator.ReadRegister(Registers.UC_X86_REG_RCX),
                2 => Emulator.ReadRegister(Registers.UC_X86_REG_RDX),
                3 => Emulator.ReadRegister(Registers.UC_X86_REG_RBX),
                4 => Emulator.ReadRegister(Registers.UC_X86_REG_RSP),
                5 => Emulator.ReadRegister(Registers.UC_X86_REG_RBP),
                6 => Emulator.ReadRegister(Registers.UC_X86_REG_RSI),
                7 => Emulator.ReadRegister(Registers.UC_X86_REG_RDI),
                8 => Emulator.ReadRegister(Registers.UC_X86_REG_R8),
                9 => Emulator.ReadRegister(Registers.UC_X86_REG_R9),
                10 => Emulator.ReadRegister(Registers.UC_X86_REG_R10),
                11 => Emulator.ReadRegister(Registers.UC_X86_REG_R11),
                12 => Emulator.ReadRegister(Registers.UC_X86_REG_R12),
                13 => Emulator.ReadRegister(Registers.UC_X86_REG_R13),
                14 => Emulator.ReadRegister(Registers.UC_X86_REG_R14),
                15 => Emulator.ReadRegister(Registers.UC_X86_REG_R15),
                _ => 0
            };
        }

        private static ulong ReadX86RegisterByIndex(int RegisterIndex)
        {
            return RegisterIndex switch
            {
                0 => Emulator.ReadRegister(Registers.UC_X86_REG_EAX),
                1 => Emulator.ReadRegister(Registers.UC_X86_REG_ECX),
                2 => Emulator.ReadRegister(Registers.UC_X86_REG_EDX),
                3 => Emulator.ReadRegister(Registers.UC_X86_REG_EBX),
                4 => Emulator.ReadRegister(Registers.UC_X86_REG_ESP),
                5 => Emulator.ReadRegister(Registers.UC_X86_REG_EBP),
                6 => Emulator.ReadRegister(Registers.UC_X86_REG_ESI),
                7 => Emulator.ReadRegister(Registers.UC_X86_REG_EDI),
                _ => 0
            };
        }

        private static bool TryDecodeCallTarget(ulong Address, byte[] Code, out bool IsCall, out ulong TargetAddress, out uint InstructionLength)
        {
            IsCall = false;
            TargetAddress = 0;
            InstructionLength = 0;

            if (Code == null || Code.Length == 0)
                return false;

            int Index = 0;
            bool AddressSizeOverride = false;
            while (Index < Code.Length)
            {
                byte Prefix = Code[Index];
                if (Prefix == 0x66 || Prefix == 0xF0 || Prefix == 0xF2 || Prefix == 0xF3 || Prefix == 0x2E || Prefix == 0x36 || Prefix == 0x3E || Prefix == 0x26 || Prefix == 0x64 || Prefix == 0x65)
                {
                    Index++;
                    continue;
                }

                if (Prefix == 0x67)
                {
                    AddressSizeOverride = true;
                    Index++;
                    continue;
                }

                break;
            }

            byte Rex = 0;
            if (Variables.Arch == BinaryArchitecture.x64 && Index < Code.Length && (Code[Index] & 0xF0) == 0x40)
                Rex = Code[Index++];

            if (Index >= Code.Length)
                return false;

            byte Op = Code[Index];
            if (Op == 0xE8 && Code.Length >= Index + 5)
            {
                int Relative = BitConverter.ToInt32(Code, Index + 1);
                ulong Next = Address + (ulong)(Index + 5);
                TargetAddress = unchecked((ulong)((long)Next + Relative));
                InstructionLength = (uint)(Index + 5);
                IsCall = true;
                return true;
            }

            if (Op != 0xFF || Code.Length < Index + 2)
                return false;

            byte ModRm = Code[Index + 1];
            int Mod = (ModRm >> 6) & 3;
            int Reg = (ModRm >> 3) & 7;
            int Rm = ModRm & 7;
            if (Reg != 2 && Reg != 3)
                return false;

            IsCall = true;
            int Cursor = Index + 2;
            int RexB = Rex & 1;
            int RexX = (Rex >> 1) & 1;

            if (Mod == 3)
            {
                int RegisterIndex = Rm + (Variables.Arch == BinaryArchitecture.x64 ? RexB * 8 : 0);
                TargetAddress = Variables.Arch == BinaryArchitecture.x64
                    ? ReadX64RegisterByIndex(RegisterIndex)
                    : ReadX86RegisterByIndex(RegisterIndex);
                InstructionLength = (uint)Cursor;
                return true;
            }

            bool Is64 = Variables.Arch == BinaryArchitecture.x64;
            ulong EffectiveAddress = 0;
            bool HasBase = true;

            if (Rm == 4)
            {
                if (Cursor >= Code.Length)
                    return true;

                byte Sib = Code[Cursor++];
                int Scale = 1 << ((Sib >> 6) & 3);
                int IndexRegister = ((Sib >> 3) & 7) + (Is64 ? RexX * 8 : 0);
                int BaseRegister = (Sib & 7) + (Is64 ? RexB * 8 : 0);

                if ((Sib & 7) == 5 && Mod == 0)
                {
                    HasBase = false;
                }
                else
                {
                    EffectiveAddress = Is64 ? ReadX64RegisterByIndex(BaseRegister) : ReadX86RegisterByIndex(BaseRegister);
                }

                if ((Sib & 0x38) != 0x20)
                {
                    ulong IndexValue = Is64 ? ReadX64RegisterByIndex(IndexRegister) : ReadX86RegisterByIndex(IndexRegister);
                    EffectiveAddress = unchecked(EffectiveAddress + (IndexValue * (ulong)Scale));
                }
            }
            else if (Is64 && Mod == 0 && Rm == 5 && !AddressSizeOverride)
            {
                HasBase = false;
            }
            else if (!Is64 && Mod == 0 && Rm == 5)
            {
                HasBase = false;
            }
            else
            {
                int RegisterIndex = Rm + (Is64 ? RexB * 8 : 0);
                EffectiveAddress = Is64 ? ReadX64RegisterByIndex(RegisterIndex) : ReadX86RegisterByIndex(RegisterIndex);
            }

            long Displacement = 0;
            if (Mod == 1)
            {
                if (Cursor >= Code.Length)
                    return true;
                Displacement = unchecked((sbyte)Code[Cursor++]);
            }
            else if (Mod == 2 || !HasBase)
            {
                if (Code.Length < Cursor + 4)
                    return true;
                Displacement = BitConverter.ToInt32(Code, Cursor);
                Cursor += 4;
            }

            InstructionLength = (uint)Cursor;
            if (Is64 && Mod == 0 && Rm == 5 && !AddressSizeOverride)
                EffectiveAddress = unchecked((ulong)((long)(Address + InstructionLength) + Displacement));
            else
                EffectiveAddress = unchecked((ulong)((long)EffectiveAddress + Displacement));

            TargetAddress = ReadPointerSizedStackValue(EffectiveAddress);
            return true;
        }

        private static bool IsRetInstruction(byte[] Code)
        {
            if (Code == null || Code.Length == 0)
                return false;

            int Index = 0;
            if (Variables.Arch == BinaryArchitecture.x64 && Code.Length > 1 && (Code[0] & 0xF0) == 0x40)
                Index = 1;

            if (Index >= Code.Length)
                return false;

            byte Op = Code[Index];
            return Op == 0xC3 || Op == 0xC2 || Op == 0xCB || Op == 0xCA;
        }

        public static string FormatAddressWithSymbol(ulong Address)
        {
            if (Address == 0)
                return "0x0";

            if (Binary != null && Binary.FileFormat == BinaryFormat.PE)
            {
                WinModule Module = FindModuleByAddress(Address);
                if (Module != null)
                {
                    string Function = ResolveFunctionName(Address, Module);
                    if (!string.IsNullOrWhiteSpace(Function))
                        return $"{Module.Name}!{Function} (0x{Address:X})";
                    return $"{Module.Name}+0x{(Address - Module.MappedBase):X} (0x{Address:X})";
                }

                if (Binary.Functions != null && Binary.Functions.Length > 0 && MappedMainModuleBase != 0)
                {
                    ulong ImageBase = Binary.PE.ImageBase;
                    BinaryFunction Best = default;
                    bool Found = false;
                    ulong BestAddress = 0;

                    foreach (BinaryFunction Function in Binary.Functions)
                    {
                        ulong FunctionAddress = Function.Address;
                        if (ImageBase != 0 && FunctionAddress >= ImageBase)
                            FunctionAddress = MappedMainModuleBase + (FunctionAddress - ImageBase);

                        if (FunctionAddress <= Address && FunctionAddress >= BestAddress)
                        {
                            Best = Function;
                            BestAddress = FunctionAddress;
                            Found = true;
                        }
                    }

                    if (Found && !string.IsNullOrWhiteSpace(Best.FunctionName))
                    {
                        ulong Offset = Address - BestAddress;
                        string Name = Offset == 0 ? Best.FunctionName : $"{Best.FunctionName}+0x{Offset:X}";
                        return $"{Name} (0x{Address:X})";
                    }
                }
            }
            else if (Binary != null && Binary.FileFormat == BinaryFormat.ELF)
            {
                LinuxLoadedModule Module = FindLinuxModuleByAddress(Address);
                if (Module != null)
                    return $"{Module.Name}+0x{(Address - Module.MappedBase):X} (0x{Address:X})";
            }

            return $"0x{Address:X}";
        }

        public static void CallTraceHookHandler(IntPtr Uc, ulong Address, uint Size, IntPtr UserData)
        {
            if (!CallTraceEnabled || Emulator == null)
                return;

            try
            {
                if (Variables.Arch != BinaryArchitecture.x64 && Variables.Arch != BinaryArchitecture.x86)
                    return;

                uint ReadSize = Size != 0 ? Size : 8U;
                byte[] Code = Emulator.ReadMemory(Address, ReadSize);
                if (Code == null || Code.Length == 0)
                    return;

                uint ThreadId = GetCurrentTraceThreadId();
                if (ThreadId == 0)
                    return;

                if (TryDecodeCallTarget(Address, Code, out bool IsCall, out ulong TargetAddress, out uint InstructionLength) && IsCall)
                {
                    ulong StackPointer = ReadStackPointerForConvention();
                    ulong ReturnAddress = Address + Math.Max(InstructionLength, 1U);
                    if (!CallTraceStacks.TryGetValue(ThreadId, out List<CallTraceFrame> Stack))
                    {
                        Stack = new List<CallTraceFrame>();
                        CallTraceStacks[ThreadId] = Stack;
                    }

                    CallTraceFrame Frame = new CallTraceFrame
                    {
                        ThreadId = ThreadId,
                        CallAddress = Address,
                        TargetAddress = TargetAddress,
                        ReturnAddress = ReturnAddress,
                        StackPointer = StackPointer,
                        CallSymbol = FormatAddressWithSymbol(Address),
                        TargetSymbol = TargetAddress == 0 ? "<indirect>" : FormatAddressWithSymbol(TargetAddress),
                        ReturnSymbol = FormatAddressWithSymbol(ReturnAddress)
                    };

                    Stack.Add(Frame);
                    if (Stack.Count > CallTraceMaxDepth)
                        Stack.RemoveAt(0);

                    return;
                }

                if (!IsRetInstruction(Code))
                    return;

                ulong Sp = ReadStackPointerForConvention();
                ulong ReturnTarget = ReadPointerSizedStackValue(Sp);
                if (!CallTraceStacks.TryGetValue(ThreadId, out List<CallTraceFrame> Frames) || Frames.Count == 0)
                    return;

                int MatchIndex = Frames.Count - 1;
                for (int i = Frames.Count - 1; i >= 0; i--)
                {
                    if (Frames[i].ReturnAddress == ReturnTarget)
                    {
                        MatchIndex = i;
                        break;
                    }
                }

                Frames.RemoveRange(MatchIndex, Frames.Count - MatchIndex);

            }
            catch (Exception Ex)
            {
                CallTraceLastError = $"0x{Address:X}: {Ex.Message}";
            }
        }

        public static void PrintCallStack(uint ThreadId, int MaxFrames)
        {
            if (ThreadId == 0)
            {
                PrintHighlight("[-] No current emulated thread.", true);
                return;
            }

            if (MaxFrames <= 0)
                MaxFrames = CallTraceMaxDepth;

            PrintHighlight($"[*] Call stack for thread {ThreadId}:", true);

            if (CallTraceStacks.TryGetValue(ThreadId, out List<CallTraceFrame> Frames) && Frames.Count > 0)
            {
                int Start = Math.Max(0, Frames.Count - MaxFrames);
                for (int i = Frames.Count - 1, FrameNumber = 0; i >= Start; i--, FrameNumber++)
                {
                    CallTraceFrame Frame = Frames[i];
                    Console.WriteLine($"#{FrameNumber,-2} {Frame.TargetSymbol}");
                    Console.WriteLine($"    call={Frame.CallSymbol}");
                    Console.WriteLine($"    ret ={Frame.ReturnSymbol} sp=0x{Frame.StackPointer:X}");
                }
                return;
            }

            PrintHighlight("[*] No traced frames for this thread. Showing raw stack return-address candidates instead.", true);
            ulong Sp = ReadStackPointerForConvention();
            ulong PointerSize = Variables.Arch == BinaryArchitecture.x64 ? 8UL : 4UL;
            for (int i = 0; i < MaxFrames; i++)
            {
                ulong Slot = Sp + ((ulong)i * PointerSize);
                ulong Value = ReadPointerSizedStackValue(Slot);
                if (Value == 0)
                    continue;
                Console.WriteLine($"#{i,-2} [0x{Slot:X}] {FormatAddressWithSymbol(Value)}");
            }
        }

        public static void PrintAllCallStacks(int MaxFrames)
        {
            if (CallTraceStacks.Count == 0)
            {
                PrintHighlight("[*] No traced call stacks.", true);
                return;
            }

            foreach (uint ThreadId in CallTraceStacks.Keys.OrderBy(Id => Id))
                PrintCallStack(ThreadId, MaxFrames);
        }

    }
}
