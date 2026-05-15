using System;
using System.Globalization;
using System.Text;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInstallUILanguage : IWinSyscall
    {
        private const ushort DefaultInstallLanguage = 0xC01;
        private const string NlsLanguageKey = @"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Nls\Language";

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong LanguageIdPtr = Instance.WinHelper.GetArg64(0);

                if (LanguageIdPtr == 0 || !Instance.IsRegionMapped(LanguageIdPtr, 2))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ushort LanguageId = QueryInstallLanguage(Instance);
                Instance._emulator.WriteMemory(LanguageIdPtr, LanguageId, 2);
                Instance.TriggerEventMessage($"[+] NtQueryInstallUILanguage: 0x{LanguageId:X4}", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                uint LanguageIdPtr = Instance.WinHelper.GetArg32(0);

                if (LanguageIdPtr == 0 || !Instance.IsRegionMapped(LanguageIdPtr, 2))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ushort LanguageId = QueryInstallLanguage(Instance);
                Instance._emulator.WriteMemory(LanguageIdPtr, LanguageId, 2);
                Instance.TriggerEventMessage($"[+] NtQueryInstallUILanguage (x86): 0x{LanguageId:X4}", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            return NTSTATUS.STATUS_NOT_IMPLEMENTED;
        }

        private static ushort QueryInstallLanguage(BinaryEmulator Instance)
        {
            if (!Instance.WinHelper.RegistryKeyExists(NlsLanguageKey, out Hive Hive, out RegistryHiveReader.HiveKey Key, out bool TempOnly))
                return DefaultInstallLanguage;

            WinRegKey RegKey = new WinRegKey
            {
                FullPath = NlsLanguageKey,
                Hive = Hive,
                ParsedKey = Key,
                HasParsedKey = !TempOnly && Hive != null && Hive.Reader != null
            };

            if (!Instance.WinHelper.TryGetRegistryValue(RegKey, "InstallLanguage", out ValueNode Value) || Value == null || Value.Data == null)
                return DefaultInstallLanguage;

            if (TryParseLanguageId(Value.Data, out ushort LanguageId))
                return LanguageId;

            return DefaultInstallLanguage;
        }

        private static bool TryParseLanguageId(byte[] Data, out ushort LanguageId)
        {
            LanguageId = 0;

            if (Data == null || Data.Length == 0)
                return false;

            string Text = null;

            if (Data.Length >= 2)
            {
                Text = Encoding.Unicode.GetString(Data).TrimEnd('\0').Trim();
            }

            if (string.IsNullOrWhiteSpace(Text))
            {
                Text = Encoding.ASCII.GetString(Data).TrimEnd('\0').Trim();
            }

            if (ushort.TryParse(Text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out LanguageId))
                return true;

            if (Data.Length >= 2)
            {
                LanguageId = BitConverter.ToUInt16(Data, 0);
                return LanguageId != 0;
            }

            return false;
        }
    }
}
