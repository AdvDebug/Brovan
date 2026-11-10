using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtCreateProcessEx : IWinSyscall
    {
        private static WinProcess ResolveParentProcess(BinaryEmulator Instance, ulong ParentProcessHandle, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;

            if (Instance == null)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return null;
            }

            if (Instance.WinHelper == null)
            {
                Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                return null;
            }

            if (Instance.WinHelper.IsCurrentProcessHandle(ParentProcessHandle, AccessMask.ProcessCreateProcess))
            {
                WinProcess Current = Instance.WinHelper.WinProcesses.FirstOrDefault(Process => Process.PID == Instance.WinHelper.PID);
                if (Current == null)
                {
                    Status = NTSTATUS.STATUS_INVALID_HANDLE;
                    return null;
                }

                return Current;
            }

            if (!Instance.WinHelper.HandleExists(ParentProcessHandle, HandleType.ProcessHandle))
            {
                Status = NTSTATUS.STATUS_INVALID_HANDLE;
                return null;
            }

            WinProcess Parent = Instance.WinHelper.GetProcessByHandle(ParentProcessHandle, AccessMask.ProcessCreateProcess);
            if (Parent == null)
            {
                Status = NTSTATUS.STATUS_ACCESS_DENIED;
                return null;
            }

            return Parent;
        }

        private static void ApplySectionIdentity(WinProcess Process, WinSection Section)
        {
            if (Process == null || Section == null)
                return;

            string SectionPath = Section.Path;
            if (string.IsNullOrEmpty(SectionPath))
            {
                WindowsFileStream Stream = Section.GetFileStream();
                SectionPath = Stream?.GuestPath;
            }

            if (!string.IsNullOrEmpty(SectionPath))
            {
                Process.Path = SectionPath;
                string FileName = Path.GetFileName(SectionPath);
                if (!string.IsNullOrEmpty(FileName))
                    Process.Name = FileName;
            }
            else if (!string.IsNullOrEmpty(Section.Name))
            {
                Process.Name = Section.Name;
            }
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance == null || Instance.WinHelper == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return Create(Instance, (uint)Instance.WinHelper.GetArg(8));
        }

        internal static NTSTATUS Create(BinaryEmulator Instance, uint Reserved)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            ulong ProcessHandlePtr = Instance.WinHelper.GetArg(0);
            uint DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong ParentProcessHandle = Instance.WinHelper.GetArg(3);
            ulong SectionHandle = Instance.WinHelper.GetArg(5);
            ulong DebugPort = Instance.WinHelper.GetArg(6);
            ulong TokenHandle = Instance.WinHelper.GetArg(7);

            uint HandleSize = (uint)Instance.WinHelper.PointerSize;
            if (ProcessHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ProcessHandlePtr, HandleSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (DesiredAccess == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (ObjectAttributesPtr != 0 && !Instance.IsRegionMapped(ObjectAttributesPtr, 1))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Reserved != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS ParentStatus;
            WinProcess ParentProcess = ResolveParentProcess(Instance, ParentProcessHandle, out ParentStatus);
            if (ParentProcess == null)
                return ParentStatus;

            WinSection Section = null;
            if (SectionHandle != 0)
            {
                Section = Instance.WinHelper.GetSectionByHandle(SectionHandle, AccessMask.GiveTemp);
                if (Section == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (DebugPort != 0 && !Instance.WinHelper.HandleExists(DebugPort, HandleType.PortHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            NTSTATUS TokenStatus = GuestProcessLauncher.ResolveLaunchToken(Instance, TokenHandle, ParentProcess, out WinToken Launch);
            if (TokenStatus != NTSTATUS.STATUS_SUCCESS)
                return TokenStatus;

            WinProcess CreatedProcess = new WinProcess
            {
                Critical = ParentProcess.Critical,
                Status = ParentProcess.Status,
                Arch = ParentProcess.Arch,
                PPID = ParentProcess.PID,
                Name = ParentProcess.Name,
                Path = ParentProcess.Path,
                InstrumentationCallback = ParentProcess.InstrumentationCallback,
                Threadless = true
            };

            uint NewPID = Instance.WinHelper.GenerateRandomPID();
            CreatedProcess.PID = NewPID;
            CreatedProcess.PrimaryToken = Launch.AssignPrimary(NewPID);

            if (Section != null)
            {
                ApplySectionIdentity(CreatedProcess, Section);
            }

            if (string.IsNullOrEmpty(CreatedProcess.Name))
                CreatedProcess.Name = $"Process_{NewPID}";

            Instance.WinHelper.InitializeProcessTimes(CreatedProcess, 0, false);
            Instance.WinHelper.WinProcesses.Add(CreatedProcess);

            AccessMask GrantedAccess = (AccessMask)DesiredAccess;
            WinHandle NewHandle = Instance.WinHelper.OpenProcessHandle(NewPID, GrantedAccess);
            if (NewHandle.Handle == 0)
            {
                Instance.WinHelper.WinProcesses.RemoveAll(Process => Process.PID == NewPID);
                return NTSTATUS.STATUS_NO_MEMORY;
            }

            if (!Instance._emulator.WriteMemory(ProcessHandlePtr, Is64 ? NewHandle.Handle : (uint)NewHandle.Handle, HandleSize))
            {
                Instance.WinHelper.CloseHandle(NewHandle.Handle);
                Instance.WinHelper.WinProcesses.RemoveAll(Process => Process.PID == NewPID);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtCreateProcessEx: Created process \"{CreatedProcess.Name}\" (PID {CreatedProcess.PID}) from parent PID {CreatedProcess.PPID}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
