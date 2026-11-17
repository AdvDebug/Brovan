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

            // NT probes the target handle first. The WOW64 thunk writes to a local, so on x86 the source is already
            // closed when the copy faults.
            bool Writable = !CreateDuplicate || Instance.AccessibleLength(TargetHandlePtr, HandleSize, true) == HandleSize;
            if (!Writable && HandleSize == 8)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

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

                bool Local = TargetProcess != null && TargetProcess.PID == Instance.WinHelper.PID;
                RemoteGuestProcess? Remote = Local ? null : TargetProcess?.Remote;
                if (!Local && Remote == null)
                {
                    if (CloseSource)
                        CloseSourceHandle(Instance, SourceHandle);

                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                }

                if (!Writable)
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

                if (Remote != null)
                    return Push(Instance, Remote, SourceHandle, SourceObject, NewAccess, NewAttributes, TargetHandlePtr, CloseSource);

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

        private static NTSTATUS Push(BinaryEmulator Instance, RemoteGuestProcess Target, ulong SourceHandle, IHandleObject SourceObject, AccessMask Access,
            ObjectHandleFlags Attributes, ulong TargetHandlePtr, bool CloseSource)
        {
            NTSTATUS Refused = NTSTATUS.STATUS_SUCCESS;
            byte[] Record = Array.Empty<byte>();
            if (Target.HasExited)
                Refused = HandleDelivery.Exited;
            else if (!HandleTransfer.TryWriteRecord(Instance, SourceHandle, new HandleEntry { Object = SourceObject, Permissions = Access, Flags = Attributes }, out Record))
                Refused = NTSTATUS.STATUS_NOT_SUPPORTED;

            if (Refused != NTSTATUS.STATUS_SUCCESS)
            {
                if (CloseSource)
                    CloseSourceHandle(Instance, SourceHandle);

                return Refused;
            }

            // NT closes the source whatever the outcome, so a held handle keeps the object until the target opens it.
            HeldHandle Held = Instance.WinHelper.Hold(SourceObject, Access);
            if (CloseSource)
                CloseSourceHandle(Instance, SourceHandle);

            return RemoteCalls.Start(Instance, new HandleDelivery(Target, Record, TargetHandlePtr, Held));
        }

        private sealed class HandleDelivery : RemoteCall
        {
            internal const NTSTATUS Exited = NTSTATUS.STATUS_PROCESS_IS_TERMINATING;

            private readonly ulong TargetHandlePtr;
            private readonly HeldHandle Held;

            internal HandleDelivery(RemoteGuestProcess Target, byte[] Record, ulong TargetHandlePtr, HeldHandle Held)
                : base(Target, SessionOperation.ReceiveHandle, 0, 0, Record, 0)
            {
                this.TargetHandlePtr = TargetHandlePtr;
                this.Held = Held;
            }

            internal override NTSTATUS ExitedStatus => Exited;

            // The target keeps the handle when the store faults, which NT avoids by probing first.
            internal override NTSTATUS Ended(BinaryEmulator Instance, MailboxOutcome Outcome, NTSTATUS Status, ulong Result, ReadOnlySpan<byte> Answer)
            {
                Instance.WinHelper.Release(Held);

                NTSTATUS Final = StatusOf(Outcome, Status);
                // A call that was not parked has no thread and runs on the current one.
                if (Final != NTSTATUS.STATUS_SUCCESS || (Thread != null && !IsLive))
                    return Final;

                return Instance.WinHelper.WritePointer(TargetHandlePtr, Result) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
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
