using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSymbolicLinkObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong LinkHandlePtr = Instance.WinHelper.GetArg64(0);
            AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

            if (LinkHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(LinkHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string Target = ResolveSymbolicLinkTarget(Instance, Attributes.RootDirectory, Name, FullName);
            if (Target == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            WinSymbolicLink LinkObj = new WinSymbolicLink
            {
                FullName = FullName,
                Target = Target
            };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(LinkObj, DesiredAccess);
            Instance.WinHelper.WinHandles.Add(Handle);

            if (!Instance._emulator.WriteMemory(LinkHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

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
