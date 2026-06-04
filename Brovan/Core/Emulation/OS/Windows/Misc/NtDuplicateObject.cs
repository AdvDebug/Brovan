using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDuplicateObject : IWinSyscall
    {
        private const uint OBJ_PROTECT_CLOSE = 0x00000001;
        private const uint OBJ_INHERIT = 0x00000002;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong SourceProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong SourceHandle = Instance.WinHelper.GetArg64(1);
                ulong TargetProcessHandle = Instance.WinHelper.GetArg64(2);
                ulong TargetHandlePtr = Instance.WinHelper.GetArg64(3);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(4);
                uint HandleAttributes = (uint)Instance.WinHelper.GetArg64(5);
                uint Options = (uint)Instance.WinHelper.GetArg64(6);

                return DuplicateObject(Instance, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandlePtr, DesiredAccess, HandleAttributes, Options, 8);
            }
            else
            {
                ulong SourceProcessHandle = Instance.WinHelper.GetArg32(0);
                ulong SourceHandle = Instance.WinHelper.GetArg32(1);
                ulong TargetProcessHandle = Instance.WinHelper.GetArg32(2);
                ulong TargetHandlePtr = Instance.WinHelper.GetArg32(3);
                ulong DesiredAccess = Instance.WinHelper.GetArg32(4);
                uint HandleAttributes = Instance.WinHelper.GetArg32(5);
                uint Options = Instance.WinHelper.GetArg32(6);

                return DuplicateObject(Instance, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandlePtr, DesiredAccess, HandleAttributes, Options, 4);
            }
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

            if (!TryResolveSourceObject(Instance, SourceHandle, out IHandleObject SourceObject, out AccessMask SourceAccess, out ObjectHandleFlags SourceAttributes))
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

                ObjectHandleFlags NewAttributes = ((Flags & DuplicateFlags.DUPLICATE_SAME_ATTRIBUTES) != 0)
                    ? SourceAttributes
                    : ConvertObjectHandleAttributes(HandleAttributes);

                NewHandle = Instance.WinHelper.HandleManager.AddHandle(SourceObject, NewAccess);
                Instance.WinHelper.HandleManager.SetHandleFlags(NewHandle.Handle, NewAttributes);
                Instance.WinHelper.WinHandles.Add(NewHandle);

                if (!WriteDuplicatedHandle(Instance, TargetHandlePtr, NewHandle.Handle, HandleSize))
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
                Instance.TriggerEventMessage($"[+] NtDuplicateObject: Duplicated handle of {SourceObject.ObjectType} 0x{SourceHandle:X} -> 0x{NewHandle.Handle:X}.", LogFlags.Syscall);
            else
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

        private static bool TryResolveSourceObject(BinaryEmulator Instance, ulong SourceHandle, out IHandleObject SourceObject, out AccessMask SourceAccess, out ObjectHandleFlags SourceAttributes)
        {
            SourceObject = null;
            SourceAccess = AccessMask.None;
            SourceAttributes = ObjectHandleFlags.None;

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

            if (!Instance.WinHelper.HandleManager.HandleExists(SourceHandle))
                return false;

            SourceObject = Instance.WinHelper.HandleManager.GetObjectByHandle(SourceHandle);
            if (SourceObject == null)
                return false;

            SourceAccess = Instance.WinHelper.HandleManager.GetPermissionsByHandle(SourceHandle);
            SourceAttributes = Instance.WinHelper.HandleManager.GetHandleFlags(SourceHandle);
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

        private static ObjectHandleFlags ConvertObjectHandleAttributes(uint HandleAttributes)
        {
            ObjectHandleFlags Flags = ObjectHandleFlags.None;

            if ((HandleAttributes & OBJ_INHERIT) != 0)
                Flags |= ObjectHandleFlags.Inherit;

            if ((HandleAttributes & OBJ_PROTECT_CLOSE) != 0)
                Flags |= ObjectHandleFlags.ProtectFromClose;

            return Flags;
        }

        private static bool WriteDuplicatedHandle(BinaryEmulator Instance, ulong TargetHandlePtr, ulong Handle, uint HandleSize)
        {
            if (HandleSize == 4)
                return Instance._emulator.WriteMemory(TargetHandlePtr, (uint)Handle, 4);

            return Instance._emulator.WriteMemory(TargetHandlePtr, Handle, 8);
        }

        private static void CloseSourceHandle(BinaryEmulator Instance, ulong SourceHandle)
        {
            if (IsCurrentProcessPseudo(SourceHandle) || IsCurrentThreadPseudo(SourceHandle))
                return;

            Instance.WinHelper.CloseHandle(SourceHandle);
        }

        private static bool IsCurrentProcessPseudo(ulong Handle)
        {
            return Handle == HandleManager.CurrentProcess || Handle == uint.MaxValue;
        }

        private static bool IsCurrentThreadPseudo(ulong Handle)
        {
            return Handle == HandleManager.CurrentThread || Handle == 0xFFFFFFFEu;
        }
    }
}
