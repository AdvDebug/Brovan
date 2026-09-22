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
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandlePtr = Instance.WinHelper.GetArg(0);
            uint DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ClientIdPtr = Instance.WinHelper.GetArg(3);
            uint TargetPid = Instance.ReadMemoryUInt(ClientIdPtr);

            if (TargetPid == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (ProcessHandlePtr == 0 || !Instance.IsRegionMapped(ProcessHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TargetPid == Instance.WinHelper.PID)
            {
                if (!Instance.WinHelper.WritePointer(ProcessHandlePtr, ulong.MaxValue))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            WinProcess TargetProcess = Instance.WinHelper.GetProcessList().FirstOrDefault(p => p.PID == TargetPid);
            TargetProcess ??= Instance.WinHelper.TryAdoptSessionProcess(TargetPid);
            if (TargetProcess == null)
                return NTSTATUS.STATUS_INVALID_CID;

            if (TargetProcess.Status == ProtectionStatus.Unaccessible)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Instance.WinHelper.IsProtectedStatus(TargetProcess.Status) || Instance.WinHelper.CurrentUser == User.Standard && TargetProcess.RunningUser == User.Admin)
            {
                uint AllowedAccess = (uint)(AccessMask.ProcessQueryInformation | AccessMask.ProcessQueryLimitedInformation);

                if ((DesiredAccess & ~AllowedAccess) != 0)
                    return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            WinHandle EmulatedHandle = Instance.WinHelper.OpenProcessHandle(TargetProcess.PID, (AccessMask)DesiredAccess);

            if (!Instance.WinHelper.WritePointer(ProcessHandlePtr, EmulatedHandle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] Process opened a handle to the process \"{TargetProcess.Name}\" with the PID \"{TargetProcess.PID}\".", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
