using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryKey : IWinSyscall
    {
        private static Span<byte> EncodeUnicodeString(BinaryEmulator Instance, string Value)
        {
            int ByteCount = Encoding.Unicode.GetByteCount(Value);
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((uint)ByteCount);
            if (ByteCount != 0)
                Encoding.Unicode.GetBytes(Value.AsSpan(), Buffer);

            return Buffer;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong KeyHandle = Instance.WinHelper.GetArg64(0);
                KEY_INFORMATION_CLASS KeyInformationClass = (KEY_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg64(1);
                ulong KeyInformationPtr = Instance.WinHelper.GetArg64(2);
                uint Length = (uint)Instance.WinHelper.GetArg64(3, true);
                ulong ResultLengthPtr = Instance.WinHelper.GetArg64(4);

                if (ResultLengthPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(ResultLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (Length != 0)
                {
                    if (KeyInformationPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(KeyInformationPtr, Length))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                Instance.TriggerEventMessage($"[+] NtQueryKey Running with the FullPath: {RegKey.FullPath}", LogFlags.Syscall);

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyNameInformation)
                {
                    string Name = Instance.WinHelper.NormalizeNtRegistryPath(RegKey.FullPath);
                    if (string.IsNullOrEmpty(Name))
                    {
                        Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                        return NTSTATUS.STATUS_UNSUCCESSFUL;
                    }

                    Span<byte> NameBytes = EncodeUnicodeString(Instance, Name);
                    uint NameLen = (uint)NameBytes.Length;

                    uint HeaderSize = 4;
                    uint Required = HeaderSize + NameLen;

                    Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                    if (Length < Required || Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    if (!Instance.IsRegionMapped(KeyInformationPtr + 0, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr + 0, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong NameOut = KeyInformationPtr + HeaderSize;

                    if (NameLen != 0)
                    {
                        if (!Instance.IsRegionMapped(NameOut, NameLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(NameOut, NameBytes, NameLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyBasicInformation)
                {
                    if (!Instance.WinHelper.TryQueryRegistryKeyHeader(RegKey, out _, out _, out string Name))
                    {
                        Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                        return NTSTATUS.STATUS_UNSUCCESSFUL;
                    }

                    Span<byte> NameBytes = EncodeUnicodeString(Instance, Name ?? string.Empty);
                    uint NameLen = (uint)NameBytes.Length;

                    uint HeaderSize = 16;
                    uint Required = HeaderSize + NameLen;

                    Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                    if (Length < Required || Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    if (!Instance.IsRegionMapped(KeyInformationPtr + 0, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr + 0, (ulong)RegKey.LastWriteTime))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(KeyInformationPtr + 8, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr + 8, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(KeyInformationPtr + 12, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr + 12, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong NameOut = KeyInformationPtr + HeaderSize;

                    if (NameLen != 0)
                    {
                        if (!Instance.IsRegionMapped(NameOut, NameLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(NameOut, NameBytes, NameLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyFullInformation)
                {
                    if (!Instance.WinHelper.TryQueryRegistryKeyFullInfo(RegKey, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes))
                    {
                        Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                        return NTSTATUS.STATUS_UNSUCCESSFUL;
                    }

                    const uint HeaderSize = 48;

                    Instance._emulator.WriteMemory(ResultLengthPtr, HeaderSize);

                    if (Length < HeaderSize || Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    ulong P = KeyInformationPtr;

                    if (!Instance.IsRegionMapped(P, HeaderSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 0, (ulong)RegKey.LastWriteTime))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 8, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 12, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 16, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 20, (uint)SubKeyCount))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 24, (uint)MaxSubKeyNameChars * 2u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 28, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 32, (uint)ValueCount))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 36, (uint)MaxValueNameChars * 2u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 40, (uint)MaxValueDataBytes))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(P + 44, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyCachedInformation)
                {
                    if (!Instance.WinHelper.TryQueryRegistryKeyFullInfo(RegKey, out int SubKeyCount, out int ValueCount, out int MaxSubKeyNameChars, out int MaxValueNameChars, out int MaxValueDataBytes, out string Name))
                    {
                        Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                        return NTSTATUS.STATUS_UNSUCCESSFUL;
                    }

                    uint NameLen = (uint)Encoding.Unicode.GetByteCount(Name ?? string.Empty);

                    uint HeaderSize = 36;
                    Instance._emulator.WriteMemory(ResultLengthPtr, HeaderSize);

                    if (Length < HeaderSize || Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    ulong P = KeyInformationPtr;

                    if (!Instance.IsRegionMapped(P + 0, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 0, (ulong)RegKey.LastWriteTime))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 8, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 8, 0u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 12, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 12, (uint)SubKeyCount))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 16, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 16, (uint)MaxSubKeyNameChars * 2u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 20, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 20, (uint)ValueCount))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 24, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 24, (uint)MaxValueNameChars * 2u))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 28, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 28, (uint)MaxValueDataBytes))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(P + 32, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    if (!Instance._emulator.WriteMemory(P + 32, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyHandleTagsInformation)
                {
                    uint HeaderSize = 4;
                    Instance._emulator.WriteMemory(ResultLengthPtr, HeaderSize);

                    if (Length < HeaderSize || Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    if (!Instance.IsRegionMapped(KeyInformationPtr, HeaderSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr, RegKey.HandleTags))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }
            return Instance.WinUnimplemented;
        }
    }
}
