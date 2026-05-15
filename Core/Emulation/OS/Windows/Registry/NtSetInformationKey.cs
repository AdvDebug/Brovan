using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong KeyHandle = Instance.WinHelper.GetArg64(0);
                KEY_SET_INFORMATION_CLASS KeySetInformationClass = (KEY_SET_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg64(1, true);
                ulong KeySetInformation = Instance.WinHelper.GetArg64(2);
                uint KeySetInformationLength = (uint)Instance.WinHelper.GetArg64(3, true);

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                Instance.TriggerEventMessage($"[+] NtSetInformationKey Running with the FullPath: {RegKey.FullPath}, Class: {KeySetInformationClass}", LogFlags.Syscall);

                uint RequiredLength = GetRequiredLength(KeySetInformationClass);
                if (RequiredLength == 0)
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;

                if (KeySetInformationLength != RequiredLength)
                    return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                if (KeySetInformation == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(KeySetInformation, KeySetInformationLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                switch (KeySetInformationClass)
                {
                    case KEY_SET_INFORMATION_CLASS.KeyWriteTimeInformation:
                        RegKey.LastWriteTime = (long)Instance._emulator.ReadMemoryULong(KeySetInformation);
                        break;

                    case KEY_SET_INFORMATION_CLASS.KeyWow64FlagsInformation:
                        RegKey.Wow64Flags = Instance._emulator.ReadMemoryUInt(KeySetInformation);
                        break;

                    case KEY_SET_INFORMATION_CLASS.KeyControlFlagsInformation:
                        RegKey.ControlFlags = Instance._emulator.ReadMemoryUInt(KeySetInformation);
                        break;

                    case KEY_SET_INFORMATION_CLASS.KeySetVirtualizationInformation:
                        RegKey.VirtualizationFlags = Instance._emulator.ReadMemoryUInt(KeySetInformation);
                        break;

                    case KEY_SET_INFORMATION_CLASS.KeySetDebugInformation:
                        RegKey.DebugInformation = Instance._emulator.ReadMemoryUInt(KeySetInformation);
                        break;

                    case KEY_SET_INFORMATION_CLASS.KeySetHandleTagsInformation:
                        RegKey.HandleTags = Instance._emulator.ReadMemoryUInt(KeySetInformation);
                        break;
                }

                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }

        private static uint GetRequiredLength(KEY_SET_INFORMATION_CLASS KeySetInformationClass)
        {
            switch (KeySetInformationClass)
            {
                case KEY_SET_INFORMATION_CLASS.KeyWriteTimeInformation:
                    return 8;

                case KEY_SET_INFORMATION_CLASS.KeyWow64FlagsInformation:
                case KEY_SET_INFORMATION_CLASS.KeyControlFlagsInformation:
                case KEY_SET_INFORMATION_CLASS.KeySetVirtualizationInformation:
                case KEY_SET_INFORMATION_CLASS.KeySetDebugInformation:
                case KEY_SET_INFORMATION_CLASS.KeySetHandleTagsInformation:
                    return 4;

                default:
                    return 0;
            }
        }
    }
}
