using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenDirectoryObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong DirectoryHandlePtr = Instance.WinHelper.GetArg64(0);
            AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

            if (DirectoryHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DirectoryHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out string ObjectName, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(ObjectName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (!Instance.WinHelper.TryGetKnownObjectDirectoryHandle(FullName, out ulong OutHandle))
            {
                Instance.TriggerEventMessage($"[!] NtOpenDirectoryObject object name not found: Name=\"{ObjectName}\", DesiredAccess=0x{((ulong)DesiredAccess):X}", LogFlags.Syscall);
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            if (!Instance._emulator.WriteMemory(DirectoryHandlePtr, OutHandle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.TriggerEventMessage($"[+] NtOpenDirectoryObject: Name=\"{ObjectName}\", DesiredAccess=0x{((ulong)DesiredAccess):X}, Handle=0x{OutHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
