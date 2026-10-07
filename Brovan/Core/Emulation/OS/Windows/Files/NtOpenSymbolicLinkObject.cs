using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSymbolicLinkObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong LinkHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            if (LinkHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(LinkHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out ulong AttributesRoot, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name) && AttributesRoot == 0)
                return NTSTATUS.STATUS_OBJECT_PATH_SYNTAX_BAD;

            WinSymbolicLink LinkObj;
            AccessMask Grantable = AccessMask.ReadControl | AccessMask.SymbolicLinkQuery;
            switch (Instance.WinHelper.LookupDosDeviceName(ref FullName, true, out IHandleObject Found, out WinObjectDirectory Parent, out _, out NTSTATUS LookupStatus))
            {
                case WinSysHelper.DosDeviceLookup.Failed:
                    return LookupStatus;
                case WinSysHelper.DosDeviceLookup.Found:
                    if (Found is not WinSymbolicLink FoundLink)
                        return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

                    if (Parent != null)
                        Grantable = Parent.EntryUserAccess;

                    LinkObj = FoundLink;
                    break;
                default:
                    string Target = ResolveSymbolicLinkTarget(AttributesRoot, Name, FullName);
                    if (Target == null)
                        return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                    LinkObj = new WinSymbolicLink
                    {
                        FullName = FullName,
                        Target = Target
                    };
                    break;
            }

            if (!WinSysHelper.TryGrantObjectAccess(DesiredAccess, false, Grantable, out AccessMask Granted))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(LinkObj, Granted);
            if (!Instance.WinHelper.WritePointer(LinkHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtOpenSymbolicLinkObject: Name=\"{Name}\", FullName=\"{LinkObj.FullName}\", Target=\"{LinkObj.Target}\", Handle=0x{Handle.Handle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ResolveSymbolicLinkTarget(ulong RootDirectory, string Name, string FullName)
        {
            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY && Name.Equals("KnownDllPath", StringComparison.OrdinalIgnoreCase))
                return WindowsVersionInfo.SystemRoot + "\\System32";

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY && Name.Equals("KnownDllPath", StringComparison.OrdinalIgnoreCase))
                return WindowsVersionInfo.SystemRoot + "\\SysWOW64";

            if (FullName.Equals("\\SystemRoot", StringComparison.OrdinalIgnoreCase))
                return WinSysHelper.ToNtDevicePath(WindowsVersionInfo.SystemRoot);

            return null;
        }
    }
}
