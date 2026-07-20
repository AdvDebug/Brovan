using Brovan.Core.Helpers;
using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryValueKey : IWinSyscall
    {
        private static Span<byte> EncodeUnicodeString(BinaryEmulator Instance, string Value)
        {
            int ByteCount = Encoding.Unicode.GetByteCount(Value);
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((uint)ByteCount);
            if (ByteCount != 0)
                Encoding.Unicode.GetBytes(Value.AsSpan(), Buffer);

            return Buffer;
        }

        private static uint AlignUp(uint Value, uint Alignment)
        {
            if (Alignment == 0)
                return Value;

            uint Mask = Alignment - 1;
            return (Value + Mask) & ~Mask;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong KeyHandle = Instance.WinHelper.GetArg(0);
            ulong ValueNamePtr = Instance.WinHelper.GetArg(1);
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

            if (!Instance.WinHelper.TryReadUnicodeString(ValueNamePtr, out string ValueName, out NTSTATUS Status))
                return Status;

            WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
            if (RegKey == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Instance.WinHelper.TryGetRegistryValue(RegKey, ValueName, out ValueNode Value))
            {
                Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            string ActualName = Value.Name ?? string.Empty;

            uint DataLen = (uint)(Value.Data == null ? 0 : Value.Data.Length);
            byte[] DataBytes = Value.Data ?? Array.Empty<byte>();

            switch (KeyValueInformationClass)
            {
                case KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation:
                case KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformationAlign64:
                    {
                        uint HeaderSize = 12;
                        uint Required = HeaderSize + DataLen;

                        Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                        if (Length == 0)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        uint WritableDataLength = 0;
                        if (Length >= HeaderSize)
                        {
                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 0, 0u))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 4, (uint)Value.Type))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 8, DataLen))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            WritableDataLength = Math.Min(DataLen, Length - HeaderSize);
                            if (WritableDataLength != 0)
                            {
                                ulong DataOut = KeyValueInformationPtr + HeaderSize;
                                if (!Instance._emulator.WriteMemory(DataOut, DataBytes.AsSpan(0, (int)WritableDataLength)))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                        }

                        if (Length < Required)
                            return Length < HeaderSize ? NTSTATUS.STATUS_BUFFER_TOO_SMALL : NTSTATUS.STATUS_BUFFER_OVERFLOW;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case KEY_VALUE_INFORMATION_CLASS.KeyValueBasicInformation:
                    {
                        Span<byte> NameBytes = EncodeUnicodeString(Instance, ActualName);
                        uint HeaderSize = 12;
                        uint NameLen = (uint)NameBytes.Length;
                        uint Required = HeaderSize + NameLen;

                        Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                        if (Length == 0)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        if (Length >= HeaderSize)
                        {
                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 0, 0u))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 4, (uint)Value.Type))
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

                case KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation:
                    {
                        Span<byte> NameBytes = EncodeUnicodeString(Instance, ActualName);
                        uint HeaderSize = 20;
                        uint NameLen = (uint)NameBytes.Length;
                        uint DataOffset = AlignUp(HeaderSize + NameLen, 4);
                        uint Required = DataOffset + DataLen;

                        Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                        if (Length == 0)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        if (Length >= HeaderSize)
                        {
                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 0, 0u))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance._emulator.WriteMemory(KeyValueInformationPtr + 4, (uint)Value.Type))
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

                default:
                    Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
            }
        }
    }
}