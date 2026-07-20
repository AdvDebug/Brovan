using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSymbolicLinkObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong LinkHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            if (LinkHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(LinkHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out ulong AttributesRoot, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string Target = ResolveSymbolicLinkTarget(Instance, AttributesRoot, Name, FullName);
            if (Target == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            WinSymbolicLink LinkObj = new WinSymbolicLink
            {
                FullName = FullName,
                Target = Target
            };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(LinkObj, DesiredAccess);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WinHelper.WritePointer(LinkHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtOpenSymbolicLinkObject: Name=\"{Name}\", FullName=\"{FullName}\", Target=\"{Target}\", Handle=0x{Handle.Handle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ResolveSymbolicLinkTarget(BinaryEmulator Instance, ulong RootDirectory, string Name, string FullName)
        {
            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY && Name.Equals("KnownDllPath", StringComparison.OrdinalIgnoreCase))
                return @"C:\Windows\System32";

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY && Name.Equals("KnownDllPath", StringComparison.OrdinalIgnoreCase))
                return @"C:\Windows\SysWOW64";

            if (FullName.Equals("\\SystemRoot", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\HarddiskVolume1\\Windows";

            if (FullName.Equals("\\??\\SystemRoot", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\HarddiskVolume1\\Windows";

            if (FullName.Equals("\\??\\C:", StringComparison.OrdinalIgnoreCase) || FullName.Equals("\\DosDevices\\C:", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\HarddiskVolume1";

            if (FullName.Equals("\\??\\UNC", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\Mup";

            if (FullName.Equals("\\??\\PIPE", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\NamedPipe";

            if (FullName.Equals("\\??\\MAILSLOT", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\Mailslot";

            return null;
        }
    }
}
