using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDuplicateObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SourceProcessHandle = Instance.WinHelper.GetArg(0);
            ulong SourceHandle = Instance.WinHelper.GetArg(1);
            ulong TargetProcessHandle = Instance.WinHelper.GetArg(2);
            ulong TargetHandlePtr = Instance.WinHelper.GetArg(3);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(4);
            uint HandleAttributes = (uint)Instance.WinHelper.GetArg(5);
            uint Options = (uint)Instance.WinHelper.GetArg(6);

            return DuplicateObject(Instance, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandlePtr, DesiredAccess, HandleAttributes, Options, (uint)Instance.WinHelper.PointerSize);
        }

        private static NTSTATUS DuplicateObject(BinaryEmulator Instance, ulong SourceProcessHandle, ulong SourceHandle, ulong TargetProcessHandle, ulong TargetHandlePtr, ulong DesiredAccess, uint HandleAttributes, uint Options, uint HandleSize)
        {
            DuplicateFlags Flags = (DuplicateFlags)Options;
            bool CloseSource = (Flags & DuplicateFlags.DUPLICATE_CLOSE_SOURCE) != 0;
            bool CreateDuplicate = TargetHandlePtr != 0;

            if (!CreateDuplicate && !CloseSource)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = ResolveProcess(Instance, SourceProcessHandle, out WinProcess SourceProcess);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (SourceProcess == null || SourceProcess.PID != Instance.WinHelper.PID)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            if (!TryResolveSourceObject(Instance, SourceHandle, out IHandleObject SourceObject, out AccessMask SourceAccess, out ObjectHandleFlags SourceAttributes, out ulong SourceKey))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinHandle NewHandle = null;

            if (CreateDuplicate)
            {
                Status = ResolveProcess(Instance, TargetProcessHandle, out WinProcess TargetProcess);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                {
                    if (CloseSource)
                        CloseSourceHandle(Instance, SourceHandle);

                    return Status;
                }

                if (TargetProcess == null || TargetProcess.PID != Instance.WinHelper.PID)
                {
                    if (CloseSource)
                        CloseSourceHandle(Instance, SourceHandle);

                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                }

                if (!Instance.IsRegionMapped(TargetHandlePtr, HandleSize))
                {
                    if (CloseSource)
                        CloseSourceHandle(Instance, SourceHandle);

                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                AccessMask NewAccess = ((Flags & DuplicateFlags.DUPLICATE_SAME_ACCESS) != 0)
                    ? SourceAccess
                    : (AccessMask)(uint)DesiredAccess;
                if (SourceObject is WinProcess)
                    NewAccess = WinSysHelper.ProcessOpenRights(NewAccess);

                ObjectHandleFlags NewAttributes = ((Flags & DuplicateFlags.DUPLICATE_SAME_ATTRIBUTES) != 0)
                    ? SourceAttributes
                    : WinSysHelper.HandleFlagsOf(HandleAttributes);

                NewHandle = Instance.WinHelper.OpenObjectHandle(SourceObject, NewAccess, NewAttributes);
                if (SourceObject is WinPort Port)
                    AlpcMessaging.ShareServedClient(Port, SourceKey, NewHandle.Handle);

                if (!Instance.WinHelper.WritePointer(TargetHandlePtr, NewHandle.Handle))
                {
                    Instance.WinHelper.CloseHandle(NewHandle.Handle);

                    if (CloseSource)
                        CloseSourceHandle(Instance, SourceHandle);

                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
            }

            if (CloseSource)
                CloseSourceHandle(Instance, SourceHandle);

            if (NewHandle != null)
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtDuplicateObject: Duplicated handle of {SourceObject.ObjectType} 0x{SourceHandle:X} -> 0x{NewHandle.Handle:X}.", LogFlags.Syscall);
            else
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtDuplicateObject: Closed source handle 0x{SourceHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ResolveProcess(BinaryEmulator Instance, ulong ProcessHandle, out WinProcess Process)
        {
            Process = null;

            if (IsCurrentProcessPseudo(ProcessHandle))
            {
                Process = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID);
                return Process != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (!Instance.WinHelper.HandleExists(ProcessHandle, HandleType.ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!HasProcessDuplicateAccess(Instance, ProcessHandle))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Process = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
            return Process != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
        }

        private static bool TryResolveSourceObject(BinaryEmulator Instance, ulong SourceHandle, out IHandleObject SourceObject, out AccessMask SourceAccess, out ObjectHandleFlags SourceAttributes, out ulong SourceKey)
        {
            SourceObject = null;
            SourceAccess = AccessMask.None;
            SourceAttributes = ObjectHandleFlags.None;
            SourceKey = 0;

            if (IsCurrentProcessPseudo(SourceHandle))
            {
                SourceObject = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID);
                SourceAccess = AccessMask.ProcessAllAccess;
                return SourceObject != null;
            }

            if (IsCurrentThreadPseudo(SourceHandle))
            {
                SourceObject = Instance.CurrentThread;
                SourceAccess = AccessMask.ThreadAllAccess;
                return SourceObject != null;
            }

            if (!Instance.WinHelper.HandleManager.TryGetHandle(SourceHandle, out SourceKey, out HandleEntry Entry) || Entry.Object == null)
                return false;

            SourceObject = Entry.Object;
            SourceAccess = Entry.Permissions;
            SourceAttributes = Entry.Flags;
            return true;
        }

        private static bool HasProcessDuplicateAccess(BinaryEmulator Instance, ulong ProcessHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(ProcessHandle);
            if (Granted == AccessMask.GiveTemp)
                return true;

            if ((Granted & AccessMask.GenericAll) != 0)
                return true;

            if ((Granted & AccessMask.ProcessAllAccess) == AccessMask.ProcessAllAccess)
                return true;

            return (Granted & AccessMask.ProcessDupHandle) != 0;
        }

        private static void CloseSourceHandle(BinaryEmulator Instance, ulong SourceHandle)
        {
            if (IsCurrentProcessPseudo(SourceHandle) || IsCurrentThreadPseudo(SourceHandle))
                return;

            Instance.WinHelper.CloseHandle(SourceHandle);
        }

        private static bool IsCurrentProcessPseudo(ulong Handle)
        {
            return HandleManager.IsCurrentProcessPseudoHandle(Handle) || Handle == uint.MaxValue;
        }

        private static bool IsCurrentThreadPseudo(ulong Handle)
        {
            return HandleManager.IsCurrentThreadPseudoHandle(Handle) || Handle == 0xFFFFFFFEu;
        }
    }
}
