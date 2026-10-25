using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtLoadKeyEx : IWinSyscall
    {
        private const uint RegNoLazyFlush = 0x00000004;
        private const uint RegAppHive = 0x00000010;
        private const uint RegProcessPrivate = 0x00000020;
        private const uint RegStartJournal = 0x00000040;
        private const uint RegHiveExactFileGrowth = 0x00000080;
        private const uint RegHiveNoRm = 0x00000100;
        private const uint RegHiveSingleLog = 0x00000200;
        private const uint RegBootHive = 0x00000400;
        private const uint RegFlushHiveFileGrowth = 0x00001000;
        private const uint RegOpenReadOnly = 0x00002000;
        private const uint RegNoImpersonationFallback = 0x00008000;

        private const uint InvalidFlags = 0xFFFF000B;
        private const uint AppHiveRefusedFlags = RegNoLazyFlush | RegStartJournal | RegBootHive;
        private const uint FlushGrowthNeeds = RegHiveSingleLog | RegBootHive;

        // Brovan writes hives in place, so the log and growth flags have nothing to act on.
        private const uint ServedFlags = RegAppHive | RegProcessPrivate | RegOpenReadOnly | RegNoImpersonationFallback
            | RegHiveExactFileGrowth | RegHiveNoRm | RegHiveSingleLog;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong TargetPtr = Helper.GetArg(0);
            ulong SourcePtr = Helper.GetArg(1);
            uint Flags = (uint)Helper.GetArg(2);
            ulong TrustClassKey = Helper.GetArg(3);
            ulong Event = Helper.GetArg(4);
            AccessMask DesiredAccess = (AccessMask)(uint)Helper.GetArg(5);
            ulong RootHandlePtr = Helper.GetArg(6);

            if ((Flags & InvalidFlags) != 0 || ((Flags & RegFlushHiveFileGrowth) != 0 && (Flags & FlushGrowthNeeds) != FlushGrowthNeeds))
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            // Any other load needs SeRestorePrivilege, which the guest token does not hold.
            if ((Flags & RegAppHive) == 0)
                return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;

            if (RootHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_7;

            if ((Flags & AppHiveRefusedFlags) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if ((Flags & ~ServedFlags) != 0 || TrustClassKey != 0 || Event != 0)
                return Instance.WinUnimplemented;

            if (!Helper.TryReadObjectAttributesName(SourcePtr, out ulong SourceRoot, out _, out string SourceName, out NTSTATUS Status))
                return Status;

            string FilePath = Helper.ResolveWindowsFilePath(SourceName, SourceRoot);
            if (string.IsNullOrEmpty(FilePath))
                return NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;

            if (!Helper.WritePointer(RootHandlePtr, 0))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Helper.TryReadObjectAttributesName(TargetPtr, out ulong TargetRoot, out string TargetName, out _, out Status))
                return Status;

            if (TargetRoot != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_1;

            string MountName = TargetName.TrimEnd('\\', '\0');
            int MountLength = RegistryManager.AppHiveMountLength(MountName);
            if (MountLength < 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (MountLength != MountName.Length)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            Status = Helper.LoadAppHive(FilePath, MountName, (Flags & RegOpenReadOnly) != 0, (Flags & RegProcessPrivate) != 0, DesiredAccess, out WinHandle Root);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Helper.WritePointer(RootHandlePtr, Root.Handle))
            {
                Helper.CloseHandle(Root.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
