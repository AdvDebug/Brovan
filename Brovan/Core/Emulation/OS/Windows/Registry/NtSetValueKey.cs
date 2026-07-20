using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetValueKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong KeyHandle = Instance.WinHelper.GetArg(0);
                ulong ValueNamePtr = Instance.WinHelper.GetArg(1);
                uint TitleIndex = (uint)Instance.WinHelper.GetArg(2);
                uint Type = (uint)Instance.WinHelper.GetArg(3);
                ulong DataPtr = Instance.WinHelper.GetArg(4);
                uint DataSize = (uint)Instance.WinHelper.GetArg(5);

                if (!Instance.WinHelper.TryReadUnicodeString(ValueNamePtr, out string ValueName, out NTSTATUS Status))
                    return Status;

                byte[] Data = Array.Empty<byte>();
                if (DataSize != 0)
                {
                    if (DataPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(DataPtr, DataSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Data = Instance._emulator.ReadMemory(DataPtr, DataSize);
                }

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtSetValueKey Running with the FullPath: {RegKey.FullPath}, ValueName: {ValueName}", LogFlags.Syscall);

                if (!Instance.WinHelper.SetRegistryValue(RegKey.FullPath, ValueName, (int)Type, Data))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                _ = TitleIndex;
                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}
