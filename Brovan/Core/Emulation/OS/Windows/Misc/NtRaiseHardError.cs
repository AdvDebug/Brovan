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

                string FirstParameter = string.Empty;
                if (NumberOfParameters != 0 && ParametersPtr != 0 && Instance.IsRegionMapped(ParametersPtr, 8))
                {
                    ulong Parameter = Instance.ReadMemoryULong(ParametersPtr);
                    FirstParameter = $", Parameter0=0x{Parameter:X}";
                }

                bool IsErrorSeverity = (((uint)ErrorStatus >> 30) & 0x3) >= 2;
                if (ValidResponseOptions == 6 && IsErrorSeverity)
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!] NtRaiseHardError requested ShutdownSystem (Normally causes BSOD). Status={ErrorStatus} (0x{(uint)ErrorStatus:X8}){FirstParameter}", LogFlags.Issues);
                else
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] NtRaiseHardError -> {ErrorStatus} (0x{(uint)ErrorStatus:X8}){FirstParameter}", LogFlags.Issues);

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
    }
}