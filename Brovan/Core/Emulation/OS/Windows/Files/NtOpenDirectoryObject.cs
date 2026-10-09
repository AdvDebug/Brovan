using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenDirectoryObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong DirectoryHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            if (DirectoryHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DirectoryHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out ulong AttributesRoot, out string ObjectName, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(ObjectName) && AttributesRoot == 0)
                return NTSTATUS.STATUS_OBJECT_PATH_SYNTAX_BAD;

            switch (Instance.WinHelper.LookupObjectDirectoryName(ref FullName, false, true, out IHandleObject Found, out _, out _, out NTSTATUS LookupStatus))
            {
                case WinSysHelper.ObjectDirectoryLookup.Failed:
                    return LookupStatus;
                case WinSysHelper.ObjectDirectoryLookup.Found:
                    return OpenModelledDirectory(Instance, DirectoryHandlePtr, DesiredAccess, Found);
            }

            if (!Instance.WinHelper.TryGetKnownObjectDirectoryHandle(FullName, out ulong OutHandle))
            {
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[!] NtOpenDirectoryObject object name not found: Name=\"{ObjectName}\", DesiredAccess=0x{((ulong)DesiredAccess):X}", LogFlags.Syscall);
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            if (!Instance.WinHelper.WritePointer(DirectoryHandlePtr, OutHandle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtOpenDirectoryObject: Name=\"{ObjectName}\", DesiredAccess=0x{((ulong)DesiredAccess):X}, Handle=0x{OutHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS OpenModelledDirectory(BinaryEmulator Instance, ulong DirectoryHandlePtr, AccessMask DesiredAccess, IHandleObject Found)
        {
            if (Found is not WinObjectDirectory Directory)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (!WinSysHelper.TryGrantObjectAccess(DesiredAccess, WinSysHelper.ObjectAccessKind.Directory, Instance.WinHelper.GetGrantableAccess(Directory), out AccessMask Granted))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Directory, Granted);
            if (!Instance.WinHelper.WritePointer(DirectoryHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtOpenDirectoryObject: Name=\"{Directory.Path}\", Granted=0x{(uint)Granted:X}, Handle=0x{Handle.Handle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
