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
                NTSTATUS ErrorStatus = (NTSTATUS)(uint)Instance.WinHelper.GetArg64(0);
                uint NumberOfParameters = (uint)Instance.WinHelper.GetArg64(1);
                uint UnicodeStringParameterMask = (uint)Instance.WinHelper.GetArg64(2);
                ulong ParametersPtr = Instance.WinHelper.GetArg64(3);
                uint ValidResponseOptions = (uint)Instance.WinHelper.GetArg64(4);
                ulong ResponsePtr = Instance.WinHelper.GetArg64(5);

                if (ResponsePtr != 0)
                {
                    if (!Instance._emulator.WriteMemory(ResponsePtr, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                string FirstParameter = string.Empty;
                if (NumberOfParameters != 0 && ParametersPtr != 0 && Instance.IsRegionMapped(ParametersPtr, 8))
                {
                    ulong Parameter = Instance.ReadMemoryULong(ParametersPtr);
                    FirstParameter = $", Parameter0=0x{Parameter:X}";
                }

                bool IsErrorSeverity = (((uint)ErrorStatus >> 30) & 0x3) >= 2;
                if (ValidResponseOptions == 6 && IsErrorSeverity)
                    Instance.TriggerEventMessage($"[!] NtRaiseHardError requested ShutdownSystem (Normally causes BSOD). Status={ErrorStatus} (0x{(uint)ErrorStatus:X8}){FirstParameter}", LogFlags.Issues);
                else
                    Instance.TriggerEventMessage($"[-] NtRaiseHardError -> {ErrorStatus} (0x{(uint)ErrorStatus:X8}){FirstParameter}", LogFlags.Issues);

                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

                NTSTATUS ErrorStatus = (NTSTATUS)Instance.ReadMemoryUInt(ESP + 4);
                uint NumberOfParameters = Instance.ReadMemoryUInt(ESP + 8);
                uint UnicodeStringParameterMask = Instance.ReadMemoryUInt(ESP + 12);
                uint ParametersPtr = Instance.ReadMemoryUInt(ESP + 16);
                uint ValidResponseOptions = Instance.ReadMemoryUInt(ESP + 20);
                uint ResponsePtr = Instance.ReadMemoryUInt(ESP + 24);

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

                Instance.TriggerEventMessage($"[-] NtRaiseHardError -> {ErrorStatus} (0x{(uint)ErrorStatus:X8}){FirstParameter}", LogFlags.Issues);

                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}