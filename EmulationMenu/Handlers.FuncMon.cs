using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
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
        public static bool IsFuncMonConvention(string Convention)
        {
            if (string.IsNullOrWhiteSpace(Convention))
                return false;

            switch (Convention.Trim().ToLowerInvariant())
            {
                case "win64":
                case "x64":
                case "ms64":
                case "cdecl":
                case "stdcall":
                case "thiscall":
                case "fastcall":
                    return true;
                default:
                    return false;
            }
        }

        public static string GetDefaultFuncMonConvention()
        {
            return Variables.Arch == BinaryArchitecture.x64 ? "win64" : "stdcall";
        }

        private static ulong ReadStackPointerForConvention()
        {
            return Variables.Arch == BinaryArchitecture.x64
                ? Emulator.ReadRegister(Registers.UC_X86_REG_RSP)
                : Emulator.ReadRegister(Registers.UC_X86_REG_ESP);
        }

        private static ulong ReadReturnAddressForConvention(string Convention)
        {
            ulong StackPointer = ReadStackPointerForConvention();
            ulong PointerSize = Variables.Arch == BinaryArchitecture.x64 ? 8UL : 4UL;
            if (!Emulator.IsRegionMapped(StackPointer, PointerSize))
                return 0;

            return Variables.Arch == BinaryArchitecture.x64
                ? Emulator.ReadMemoryULong(StackPointer)
                : Emulator.ReadMemoryUInt(StackPointer);
        }

        private static ulong ReadArgumentForConvention(string Convention, int Index)
        {
            Convention = string.IsNullOrWhiteSpace(Convention) ? GetDefaultFuncMonConvention() : Convention.Trim().ToLowerInvariant();

            if (Variables.Arch == BinaryArchitecture.x64 || Convention == "win64" || Convention == "x64" || Convention == "ms64")
            {
                return Index switch
                {
                    0 => Emulator.ReadRegister(Registers.UC_X86_REG_RCX),
                    1 => Emulator.ReadRegister(Registers.UC_X86_REG_RDX),
                    2 => Emulator.ReadRegister(Registers.UC_X86_REG_R8),
                    3 => Emulator.ReadRegister(Registers.UC_X86_REG_R9),
                    _ => ReadStackArgument64(Index)
                };
            }

            return Convention switch
            {
                "cdecl" => ReadStackArgument32(Index),
                "stdcall" => ReadStackArgument32(Index),
                "thiscall" => Index == 0 ? Emulator.ReadRegister(Registers.UC_X86_REG_ECX) : ReadStackArgument32(Index - 1),
                "fastcall" => Index switch
                {
                    0 => Emulator.ReadRegister(Registers.UC_X86_REG_ECX),
                    1 => Emulator.ReadRegister(Registers.UC_X86_REG_EDX),
                    _ => ReadStackArgument32(Index - 2)
                },
                _ => ReadStackArgument32(Index)
            };
        }

        private static ulong ReadStackArgument64(int Index)
        {
            ulong Rsp = Emulator.ReadRegister(Registers.UC_X86_REG_RSP);
            ulong Address = Rsp + 0x28UL + ((ulong)(Index - 4) * 8UL);
            if (!Emulator.IsRegionMapped(Address, 8))
                return 0;
            return Emulator.ReadMemoryULong(Address);
        }

        private static ulong ReadStackArgument32(int Index)
        {
            ulong Esp = Emulator.ReadRegister(Registers.UC_X86_REG_ESP);
            ulong Address = Esp + 4UL + ((ulong)Index * 4UL);
            if (!Emulator.IsRegionMapped(Address, 4))
                return 0;
            return Emulator.ReadMemoryUInt(Address);
        }

        private static ulong ReadFuncMonReturnValue()
        {
            return Variables.Arch == BinaryArchitecture.x64
                ? Emulator.ReadRegister(Registers.UC_X86_REG_RAX)
                : Emulator.ReadRegister(Registers.UC_X86_REG_EAX);
        }

        private static ulong ReadPointerSizedValue(ulong Address)
        {
            ulong PointerSize = Variables.Arch == BinaryArchitecture.x64 ? 8UL : 4UL;
            if (!Emulator.IsRegionMapped(Address, PointerSize))
                return 0;

            return Variables.Arch == BinaryArchitecture.x64
                ? Emulator.ReadMemoryULong(Address)
                : Emulator.ReadMemoryUInt(Address);
        }

        private static string DecodeDirectFuncMonValue(string Type, ulong Value)
        {
            switch (Type)
            {
                case "u8":
                    return $"0x{((byte)Value):X}";
                case "u16":
                    return $"0x{((ushort)Value):X}";
                case "u32":
                case "uint":
                    return $"0x{((uint)Value):X}";
                case "i32":
                case "int":
                    return unchecked(((int)Value)).ToString();
                case "u64":
                case "ulong":
                case "ptr":
                case "hex":
                    return $"0x{Value:X}";
                case "i64":
                    return unchecked(((long)Value)).ToString();
                case "ascii":
                case "astr":
                case "str":
                case "string":
                    return $"\"{ReadAsciiZ(Value)}\"";
                case "wstr":
                case "wstring":
                    return $"\"{ReadWideZ(Value)}\"";
                case "unicode_string":
                case "unicode":
                case "ustr":
                    if (TryReadUnicodeStringStruct(Value, out string UnicodeValue))
                        return $"\"{UnicodeValue}\"";
                    return $"0x{Value:X}";
                default:
                    return $"0x{Value:X}";
            }
        }

        private static string DecodeDereferencedFuncMonValue(string Type, ulong Value)
        {
            int DereferenceCount = 0;
            while (Type.StartsWith("*", StringComparison.Ordinal))
            {
                DereferenceCount++;
                Type = Type.Substring(1).TrimStart();
            }

            if (DereferenceCount == 0)
                return DecodeDirectFuncMonValue(Type, Value);

            if (Value == 0)
                return "NULL";

            ulong CurrentAddress = Value;
            for (int i = 0; i < DereferenceCount - 1; i++)
            {
                ulong NextAddress = ReadPointerSizedValue(CurrentAddress);
                if (NextAddress == 0)
                    return $"NULL @ 0x{CurrentAddress:X}";
                CurrentAddress = NextAddress;
            }

            switch (Type)
            {
                case "u8":
                    if (!Emulator.IsRegionMapped(CurrentAddress, 1))
                        return $"<invalid @ 0x{CurrentAddress:X}>";
                    return $"*0x{Value:X} = 0x{Emulator.ReadMemory(CurrentAddress, 1)[0]:X}";
                case "u16":
                    if (!Emulator.IsRegionMapped(CurrentAddress, 2))
                        return $"<invalid @ 0x{CurrentAddress:X}>";
                    return $"*0x{Value:X} = 0x{Emulator._emulator.ReadMemoryUShort(CurrentAddress):X}";
                case "u32":
                case "uint":
                    if (!Emulator.IsRegionMapped(CurrentAddress, 4))
                        return $"<invalid @ 0x{CurrentAddress:X}>";
                    return $"*0x{Value:X} = 0x{Emulator.ReadMemoryUInt(CurrentAddress):X}";
                case "i32":
                case "int":
                    if (!Emulator.IsRegionMapped(CurrentAddress, 4))
                        return $"<invalid @ 0x{CurrentAddress:X}>";
                    return $"*0x{Value:X} = {unchecked((int)Emulator.ReadMemoryUInt(CurrentAddress))}";
                case "u64":
                case "ulong":
                    if (!Emulator.IsRegionMapped(CurrentAddress, 8))
                        return $"<invalid @ 0x{CurrentAddress:X}>";
                    return $"*0x{Value:X} = 0x{Emulator.ReadMemoryULong(CurrentAddress):X}";
                case "i64":
                    if (!Emulator.IsRegionMapped(CurrentAddress, 8))
                        return $"<invalid @ 0x{CurrentAddress:X}>";
                    return $"*0x{Value:X} = {unchecked((long)Emulator.ReadMemoryULong(CurrentAddress))}";
                case "ptr":
                case "hex":
                    {
                        ulong PointerValue = ReadPointerSizedValue(CurrentAddress);
                        if (PointerValue == 0)
                            return $"*0x{Value:X} = NULL";
                        return $"*0x{Value:X} = 0x{PointerValue:X}";
                    }
                case "ascii":
                case "astr":
                case "str":
                case "string":
                    {
                        ulong PointerValue = ReadPointerSizedValue(CurrentAddress);
                        if (PointerValue == 0)
                            return $"*0x{Value:X} = NULL";
                        return $"*0x{Value:X} = \"{ReadAsciiZ(PointerValue)}\"";
                    }
                case "wstr":
                case "wstring":
                    {
                        ulong PointerValue = ReadPointerSizedValue(CurrentAddress);
                        if (PointerValue == 0)
                            return $"*0x{Value:X} = NULL";
                        return $"*0x{Value:X} = \"{ReadWideZ(PointerValue)}\"";
                    }
                case "unicode_string":
                case "unicode":
                case "ustr":
                    {
                        ulong PointerValue = ReadPointerSizedValue(CurrentAddress);
                        if (PointerValue == 0)
                            return $"*0x{Value:X} = NULL";
                        if (TryReadUnicodeStringStruct(PointerValue, out string UnicodeValue))
                            return $"*0x{Value:X} = \"{UnicodeValue}\"";
                        return $"*0x{Value:X} = 0x{PointerValue:X}";
                    }
                default:
                    {
                        ulong PointerValue = ReadPointerSizedValue(CurrentAddress);
                        if (PointerValue == 0)
                            return $"*0x{Value:X} = NULL";
                        return $"*0x{Value:X} = {DecodeDirectFuncMonValue(Type, PointerValue)}";
                    }
            }
        }

        private static string DecodeFuncMonValue(string Type, ulong Value)
        {
            string NormalizedType = string.IsNullOrWhiteSpace(Type) ? "ptr" : Type.Trim().ToLowerInvariant();
            if (NormalizedType.StartsWith("*", StringComparison.Ordinal))
                return DecodeDereferencedFuncMonValue(NormalizedType, Value);
            return DecodeDirectFuncMonValue(NormalizedType, Value);
        }

        private static string GetFuncMonDisplayName(ulong Address, string ConfiguredName)
        {
            if (!string.IsNullOrWhiteSpace(ConfiguredName))
                return ConfiguredName;

            WinModule Module = FindModuleByAddress(Address);
            if (Module != null)
            {
                string Function = ResolveFunctionName(Address, Module);
                if (!string.IsNullOrWhiteSpace(Function))
                    return $"{Module.Name}!{Function}";
                return $"{Module.Name}+0x{(Address - Module.MappedBase):X}";
            }

            return $"0x{Address:X}";
        }

        public static void FuncMonEntryHookHandler(IntPtr Uc, ulong Address, uint Size, IntPtr UserData)
        {
            if (!FuncMons.TryGetValue(Address, out var Monitor))
                return;

            try
            {
                List<string> DecodedArgs = new List<string>(Monitor.ArgTypes.Count);
                for (int i = 0; i < Monitor.ArgTypes.Count; i++)
                {
                    ulong ArgValue = ReadArgumentForConvention(Monitor.Convention, i);
                    DecodedArgs.Add(DecodeFuncMonValue(Monitor.ArgTypes[i], ArgValue));
                }

                string ArgText = DecodedArgs.Count == 0 ? string.Empty : string.Join(", ", DecodedArgs);
                PrintHighlight($"[FUNCMON] ENTER {GetFuncMonDisplayName(Address, Monitor.Name)}({ArgText})", false, true);

                ulong ReturnAddress = ReadReturnAddressForConvention(Monitor.Convention);
                if (ReturnAddress == 0)
                    return;

                if (!FuncMonPendingReturns.TryGetValue(ReturnAddress, out Stack<ulong> PendingFunctions))
                {
                    PendingFunctions = new Stack<ulong>();
                    FuncMonPendingReturns[ReturnAddress] = PendingFunctions;
                }

                PendingFunctions.Push(Address);

                if (!FuncMonReturnHooks.ContainsKey(ReturnAddress))
                {
                    if (FuncMonReturnHookPtr == IntPtr.Zero)
                    {
                        FuncMonReturnHook = FuncMonReturnHookHandler;
                        FuncMonReturnHookPtr = Marshal.GetFunctionPointerForDelegate(FuncMonReturnHook);
                    }

                    IntPtr HookHandle = Emulator._emulator.AddHookWithHandle(ReturnAddress, ReturnAddress, Hooks.UC_HOOK_BLOCK, FuncMonReturnHookPtr);
                    if (HookHandle != IntPtr.Zero)
                        FuncMonReturnHooks[ReturnAddress] = HookHandle;
                }
            }
            catch (Exception Ex)
            {
                PrintHighlight($"[FUNCMON] entry decode failed at 0x{Address:X}: {Ex.Message}", false, true);
            }
        }

        public static void FuncMonReturnHookHandler(IntPtr Uc, ulong Address, uint Size, IntPtr UserData)
        {
            if (!FuncMonPendingReturns.TryGetValue(Address, out Stack<ulong> PendingFunctions) || PendingFunctions.Count == 0)
                return;

            ulong FunctionAddress = PendingFunctions.Pop();
            string ConfiguredName = FuncMons.TryGetValue(FunctionAddress, out var Monitor) ? Monitor.Name : string.Empty;
            ulong ReturnValue = ReadFuncMonReturnValue();
            PrintHighlight($"[FUNCMON] LEAVE {GetFuncMonDisplayName(FunctionAddress, ConfiguredName)} -> 0x{ReturnValue:X}", false, true);

            if (PendingFunctions.Count == 0)
                FuncMonPendingReturns.Remove(Address);
        }

    }
}
