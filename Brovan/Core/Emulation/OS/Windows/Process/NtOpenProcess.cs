using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenProcess : IWinSyscall
    {
        // The process type's generic mapping.
        private const uint GenericReadMapping = 0x00020410;
        private const uint GenericWriteMapping = 0x00020BEA;
        private const uint GenericExecuteMapping = 0x00121001;
        private const uint GenericAllMapping = 0x001FFFFF;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandlePtr = Instance.WinHelper.GetArg(0);
            uint DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ClientIdPtr = Instance.WinHelper.GetArg(3);

            if (ClientIdPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint TargetPid = (uint)Instance.WinHelper.ReadPointer(ClientIdPtr);
            ulong TargetTid = Instance.WinHelper.ReadPointer(ClientIdPtr + (ulong)Instance.WinHelper.PointerSize);

            if (TargetPid == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (ProcessHandlePtr == 0 || !Instance.IsRegionMapped(ProcessHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool Own = TargetPid == Instance.WinHelper.PID;

            WinProcess TargetProcess = Instance.WinHelper.GetProcessList().FirstOrDefault(p => p.PID == TargetPid);
            if (!Own)
                TargetProcess ??= Instance.WinHelper.TryAdoptSessionProcess(TargetPid);
            if (TargetProcess == null)
                return NTSTATUS.STATUS_INVALID_CID;

            if (Own && TargetTid != 0 &&
                (TargetTid > uint.MaxValue || !Instance.Threads.TryGetValue((uint)TargetTid, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated))
                return NTSTATUS.STATUS_INVALID_CID;

            if (TargetProcess.Status == ProtectionStatus.Unaccessible)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            uint LimitedRights = (uint)(AccessMask.ProcessQueryLimitedInformation | AccessMask.Synchronize);
            bool Limited = !Own && (Instance.WinHelper.IsProtectedStatus(TargetProcess.Status) || TargetProcess.RunningUser != Instance.WinHelper.CurrentUser);

            uint Granted = MapGenericRights(DesiredAccess);
            if ((DesiredAccess & (uint)AccessMask.MaximumAllowed) != 0)
                Granted = (Granted & ~(uint)AccessMask.MaximumAllowed) | (Limited ? LimitedRights : GenericAllMapping);
            else if (Limited && (Granted & ~LimitedRights) != 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            WinHandle EmulatedHandle = Instance.WinHelper.OpenProcessHandle(TargetProcess.PID, (AccessMask)Granted);
            if (EmulatedHandle.Handle == 0)
                return NTSTATUS.STATUS_INVALID_CID;

            if (!Instance.WinHelper.WritePointer(ProcessHandlePtr, EmulatedHandle.Handle))
            {
                Instance.WinHelper.CloseHandle(EmulatedHandle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] Process opened a handle to the process \"{TargetProcess.Name}\" with the PID \"{TargetProcess.PID}\".", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: each query or set right also grants its limited form.
        private static uint MapGenericRights(uint DesiredAccess)
        {
            uint Mapped = DesiredAccess & ~(uint)(AccessMask.GenericRead | AccessMask.GenericWrite | AccessMask.GenericExecute | AccessMask.GenericAll);

            if ((DesiredAccess & (uint)AccessMask.GenericRead) != 0)
                Mapped |= GenericReadMapping;
            if ((DesiredAccess & (uint)AccessMask.GenericWrite) != 0)
                Mapped |= GenericWriteMapping;
            if ((DesiredAccess & (uint)AccessMask.GenericExecute) != 0)
                Mapped |= GenericExecuteMapping;
            if ((DesiredAccess & (uint)AccessMask.GenericAll) != 0)
                Mapped |= GenericAllMapping;

            if ((Mapped & (uint)AccessMask.ProcessQueryInformation) != 0)
                Mapped |= (uint)AccessMask.ProcessQueryLimitedInformation;
            if ((Mapped & (uint)AccessMask.ProcessSetInformation) != 0)
                Mapped |= (uint)AccessMask.ProcessSetLimitedInformation;

            return Mapped;
        }
    }
}
