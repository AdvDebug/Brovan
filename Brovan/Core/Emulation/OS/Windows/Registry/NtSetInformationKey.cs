using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong KeyHandle = Instance.WinHelper.GetArg(0);
            KEY_SET_INFORMATION_CLASS KeySetInformationClass = (KEY_SET_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg(1);
            ulong KeySetInformation = Instance.WinHelper.GetArg(2);
            uint KeySetInformationLength = (uint)Instance.WinHelper.GetArg(3);

            uint RequiredLength = GetRequiredLength(KeySetInformationClass);
            if (RequiredLength == 0)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (KeySetInformationLength != RequiredLength)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            Span<byte> Input = stackalloc byte[8];
            if (KeySetInformation == 0 || !Instance.ReadMemory(KeySetInformation, Input.Slice(0, (int)RequiredLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            AccessMask Required = KeySetInformationClass == KEY_SET_INFORMATION_CLASS.KeySetHandleTagsInformation ? AccessMask.None : AccessMask.KeySetValue;
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(KeyHandle, Required, out WinRegKey RegKey);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtSetInformationKey Running with the FullPath: {RegKey.FullPath}, Class: {KeySetInformationClass}", LogFlags.Syscall);

            uint Value = BinaryPrimitives.ReadUInt32LittleEndian(Input);
            switch (KeySetInformationClass)
            {
                case KEY_SET_INFORMATION_CLASS.KeyWriteTimeInformation:
                    RegKey.LastWriteTime = BinaryPrimitives.ReadInt64LittleEndian(Input);
                    break;

                case KEY_SET_INFORMATION_CLASS.KeyWow64FlagsInformation:
                    RegKey.Wow64Flags = Value;
                    break;

                case KEY_SET_INFORMATION_CLASS.KeyControlFlagsInformation:
                    RegKey.ControlFlags = Value;
                    break;

                case KEY_SET_INFORMATION_CLASS.KeySetVirtualizationInformation:
                    RegKey.VirtualizationFlags = Value;
                    break;

                case KEY_SET_INFORMATION_CLASS.KeySetDebugInformation:
                    RegKey.DebugInformation = Value;
                    break;

                case KEY_SET_INFORMATION_CLASS.KeySetHandleTagsInformation:
                    RegKey.HandleTags = Value;
                    break;
            }

            return NTSTATUS.STATUS_SUCCESS;
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
