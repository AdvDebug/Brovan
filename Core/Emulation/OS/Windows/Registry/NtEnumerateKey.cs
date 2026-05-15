using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtEnumerateKey : IWinSyscall
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
                uint Index = (uint)Instance.WinHelper.GetArg64(1);
                KEY_INFORMATION_CLASS KeyInformationClass = (KEY_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg64(2);
                ulong KeyInformationPtr = Instance.WinHelper.GetArg64(3);
                uint Length = (uint)Instance.WinHelper.GetArg64(4, true);
                ulong ResultLengthPtr = Instance.WinHelper.GetArg64(5);

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

                Instance.TriggerEventMessage($"[+] NtEnumerateKey Running with the FullPath: {RegKey.FullPath}", LogFlags.Syscall);

                if (!Instance.WinHelper.TryEnumerateRegistrySubKey(RegKey, (int)Index, out string SubKeyName))
                {
                    Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                    return NTSTATUS.STATUS_NO_MORE_ENTRIES;
                }

                Span<byte> NameBytes = EncodeUnicodeString(Instance, SubKeyName);
                uint NameLen = (uint)NameBytes.Length;

                uint HeaderSize;

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyBasicInformation)
                    HeaderSize = 16;
                else if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyNameInformation)
                    HeaderSize = 4;
                else
                {
                    Instance._emulator.WriteMemory(ResultLengthPtr, 0u);
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                }

                uint Required = HeaderSize + NameLen;

                Instance._emulator.WriteMemory(ResultLengthPtr, Required);

                if (Length < Required || Length == 0)
                    return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyBasicInformation)
                {
                    if (!Instance.IsRegionMapped(KeyInformationPtr + 0, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr + 0, 0UL))
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

                    if (!Instance.IsRegionMapped(NameOut, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(NameOut, NameBytes, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (KeyInformationClass == KEY_INFORMATION_CLASS.KeyNameInformation)
                {
                    if (!Instance.IsRegionMapped(KeyInformationPtr + 0, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(KeyInformationPtr + 0, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong NameOut = KeyInformationPtr + HeaderSize;

                    if (!Instance.IsRegionMapped(NameOut, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(NameOut, NameBytes, NameLen))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }
            }
            return Instance.WinUnimplemented;
        }
    }
}
