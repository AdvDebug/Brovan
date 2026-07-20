using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtEnumerateValueKey : IWinSyscall
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
            {
                ulong KeyHandle = Instance.WinHelper.GetArg(0);
                uint Index = (uint)Instance.WinHelper.GetArg(1);
                KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass = (KEY_VALUE_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg(2);
                ulong KeyValueInformationPtr = Instance.WinHelper.GetArg(3);
                uint Length = (uint)Instance.WinHelper.GetArg(4);
                ulong ResultLengthPtr = Instance.WinHelper.GetArg(5);

                if (ResultLengthPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(ResultLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (Length != 0)
                {
                    if (KeyValueInformationPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(KeyValueInformationPtr, Length))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtEnumerateValueKey Running with the FullPath: {RegKey.FullPath}", LogFlags.Syscall);

                if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS.KeyValueBasicInformation)
                {
                    if (!Instance.WinHelper.TryEnumerateRegistryValueBasic(RegKey, (int)Index, out string ValueName, out int ValueType, out _))
                    {
                        Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                        return NTSTATUS.STATUS_NO_MORE_ENTRIES;
                    }

                    if (ValueName == null)
                        ValueName = string.Empty;

                    Span<byte> NameBytes = EncodeUnicodeString(Instance, ValueName);
                    uint NameLen = (uint)NameBytes.Length;

                    uint HeaderSize = 12;
                    uint Required = HeaderSize + NameLen;

                    Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                    if (Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    if (Length >= HeaderSize)
                    {
                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 0, 0u))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 4, (uint)ValueType))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 8, NameLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        uint WritableNameLength = Math.Min(NameLen, Length - HeaderSize);
                        if (WritableNameLength != 0)
                        {
                            ulong NameOut = KeyValueInformationPtr + HeaderSize;
                            if (!Instance._emulator.WriteMemory(NameOut, NameBytes.Slice(0, (int)WritableNameLength)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }
                    }

                    if (Length < Required)
                        return Length < HeaderSize ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_BUFFER_OVERFLOW;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (KeyValueInformationClass == KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation)
                {
                    if (!Instance.WinHelper.TryEnumerateRegistryValueFull(RegKey, (int)Index, out string ValueName, out int ValueType, out byte[] DataBytes))
                    {
                        Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                        return NTSTATUS.STATUS_NO_MORE_ENTRIES;
                    }

                    if (ValueName == null)
                        ValueName = string.Empty;

                    if (DataBytes == null)
                        DataBytes = Array.Empty<byte>();

                    Span<byte> NameBytes = EncodeUnicodeString(Instance, ValueName);
                    uint NameLen = (uint)NameBytes.Length;

                    uint DataLen = (uint)DataBytes.Length;

                    uint HeaderSize = 20;
                    uint DataOffset = ((HeaderSize + NameLen) + 3u) & ~3u;
                    uint Required = DataOffset + DataLen;

                    Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                    if (Length == 0)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    if (Length >= HeaderSize)
                    {
                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 0, 0u))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 4, (uint)ValueType))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 8, DataOffset))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 12, DataLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 16, NameLen))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        uint WritableNameLength = Math.Min(NameLen, Length - HeaderSize);
                        if (WritableNameLength != 0)
                        {
                            ulong NameOut = KeyValueInformationPtr + HeaderSize;
                            if (!Instance._emulator.WriteMemory(NameOut, NameBytes.Slice(0, (int)WritableNameLength)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                        if (DataLen != 0 && Length > DataOffset)
                        {
                            uint WritableDataLength = Math.Min(DataLen, Length - DataOffset);
                            if (WritableDataLength != 0)
                            {
                                ulong DataOut = KeyValueInformationPtr + DataOffset;
                                if (!Instance._emulator.WriteMemory(DataOut, DataBytes.AsSpan(0, (int)WritableDataLength)))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                        }
                    }

                    if (Length < Required)
                        return Length < HeaderSize ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_BUFFER_OVERFLOW;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            return Instance.WinUnimplemented;
        }
    }
}
