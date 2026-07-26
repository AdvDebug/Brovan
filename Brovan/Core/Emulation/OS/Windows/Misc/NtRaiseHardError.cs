using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtRaiseHardError : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                NTSTATUS ErrorStatus = (NTSTATUS)(uint)Instance.WinHelper.GetArg(0);
                uint NumberOfParameters = (uint)Instance.WinHelper.GetArg(1);
                uint UnicodeStringParameterMask = (uint)Instance.WinHelper.GetArg(2);
                ulong ParametersPtr = Instance.WinHelper.GetArg(3);
                uint ValidResponseOptions = (uint)Instance.WinHelper.GetArg(4);
                ulong ResponsePtr = Instance.WinHelper.GetArg(5);

                if (ResponsePtr != 0)
                {
                    if (!Instance._emulator.WriteMemory(ResponsePtr, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                string Parameters = DescribeParameters(Instance, NumberOfParameters, UnicodeStringParameterMask, ParametersPtr);

                bool IsErrorSeverity = (((uint)ErrorStatus >> 30) & 0x3) >= 2;
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                {
                    if (ValidResponseOptions == 6 && IsErrorSeverity)
                        Instance.TriggerEventMessage($"[!] NtRaiseHardError requested ShutdownSystem (Normally causes BSOD). Status={ErrorStatus} (0x{(uint)ErrorStatus:X8}){Parameters}", LogFlags.Issues);
                    else
                        Instance.TriggerEventMessage($"[-] NtRaiseHardError -> {ErrorStatus} (0x{(uint)ErrorStatus:X8}){Parameters}", LogFlags.Issues);

                    TraceFailFastRecord(Instance, (uint)ErrorStatus);
                    Instance.TraceStackModuleFrames("[-] NtRaiseHardError");
                }

                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {

                NTSTATUS ErrorStatus = (NTSTATUS)Instance.WinHelper.GetArg(0);
                uint NumberOfParameters = (uint)Instance.WinHelper.GetArg(1);
                uint UnicodeStringParameterMask = (uint)Instance.WinHelper.GetArg(2);
                uint ParametersPtr = (uint)Instance.WinHelper.GetArg(3);
                uint ValidResponseOptions = (uint)Instance.WinHelper.GetArg(4);
                uint ResponsePtr = (uint)Instance.WinHelper.GetArg(5);

                if (ResponsePtr != 0)
                {
                    if (!Instance._emulator.WriteMemory(ResponsePtr, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                string FirstParameter = string.Empty;
                if (NumberOfParameters != 0 && ParametersPtr != 0 && Instance.IsRegionMapped(ParametersPtr, 4))
                {
                    uint Parameter = Instance.ReadMemoryUInt(ParametersPtr);
                    FirstParameter = $", Parameter0=0x{Parameter:X8}";
                }

                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] NtRaiseHardError -> {ErrorStatus} (0x{(uint)ErrorStatus:X8}){FirstParameter}", LogFlags.Issues);

                return NTSTATUS.STATUS_SUCCESS;
            }
        }

        private static void TraceFailFastRecord(BinaryEmulator Instance, uint ErrorStatus)
        {
            const int ExceptionAddressOffset = 0x10;
            const int ScanSlots = 4096;

            ulong StackPointer = Instance.ReadRegister(Registers.UC_X86_REG_RSP);

            for (int i = 0; i < ScanSlots; i++)
            {
                ulong Slot = StackPointer + (ulong)i * 8;
                if (!Instance.IsRegionMapped(Slot, ExceptionAddressOffset + 8))
                    break;

                if ((Instance.ReadMemoryUInt(Slot) & 0x0FFFFFFF) != (ErrorStatus & 0x0FFFFFFF))
                    continue;

                ulong ExceptionAddress = Instance.ReadMemoryULong(Slot + ExceptionAddressOffset);
                if (ExceptionAddress == 0)
                    continue;

                Instance.TriggerEventMessage($"[-] NtRaiseHardError raised at {Instance.DescribeAddress(ExceptionAddress)}", LogFlags.Issues);

                const int ExceptionRecordSize = 0x98;
                int Printed = 0;
                for (int k = 0; k < 128 && Printed < 6; k++)
                {
                    ulong CallerSlot = Slot + ExceptionRecordSize + (ulong)k * 8;
                    if (!Instance.IsRegionMapped(CallerSlot, 8))
                        break;

                    ulong Value = Instance.ReadMemoryULong(CallerSlot);
                    if (Value == 0 || Value == ExceptionAddress)
                        continue;

                    string Described = Instance.DescribeAddress(Value);
                    if (Described.StartsWith("0x", StringComparison.Ordinal))
                        continue;

                    Instance.TriggerEventMessage($"[-] NtRaiseHardError     caller {Described}", LogFlags.Issues);
                    Printed++;
                }

                return;
            }
        }

        private static string DescribeParameters(BinaryEmulator Instance, uint NumberOfParameters, uint UnicodeStringParameterMask, ulong ParametersPtr)
        {
            if (NumberOfParameters == 0 || ParametersPtr == 0)
                return string.Empty;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            uint Count = NumberOfParameters > 4 ? 4 : NumberOfParameters;
            string Result = string.Empty;

            for (uint i = 0; i < Count; i++)
            {
                ulong Slot = ParametersPtr + i * PointerSize;
                if (!Instance.IsRegionMapped(Slot, PointerSize))
                    break;

                ulong Parameter = Instance.WinHelper.ReadPointer(Slot);
                Result += $", Parameter{i}=0x{Parameter:X}";

                if ((UnicodeStringParameterMask & (1u << (int)i)) != 0 && Parameter != 0 &&
                    Instance.WinHelper.TryReadUnicodeString(Parameter, out string Text, out _) && !string.IsNullOrEmpty(Text))
                {
                    Result += $" \"{Text}\"";
                }
            }

            return Result;
        }
    }
}