using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
                ulong ParentProcess = Instance.WinHelper.GetArg64(3);
                ulong InheritObjectTable = Instance.WinHelper.GetArg64(4);
                ulong SectionHandle = Instance.WinHelper.GetArg64(5);
                ulong DebugPort = Instance.WinHelper.GetArg64(6);
                ulong TokenHandle = Instance.WinHelper.GetArg64(7);

                if(ProcessHandlePtr == 0)
                {
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if(DesiredAccess == 0)
                {
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if(ObjectAttributesPtr == 0)
                {
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if(!Instance.IsRegionMapped(ObjectAttributesPtr, 1))
                {
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
                
                if (!StructSerializer.ParseStruct(Instance, ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 ObjectAttrs))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                WinProcess CreatedProcess = new WinProcess();
                CreatedProcess.Critical = false;
                CreatedProcess.Status = ProtectionStatus.None;
                CreatedProcess.Arch = BinaryArchitecture.x64;
                CreatedProcess.PPID = Instance.WinHelper.PID;

                //CreatedProcess.Name = Instance._emulator.ReadMemoryString(ObjectAttrs.ObjectName.Buffer, (int)ObjectAttrs.Length, Encoding.Unicode);
                CreatedProcess.PID = Instance.WinHelper.GenerateRandomPID();
                CreatedProcess.RunningUser = Instance.WinHelper.CurrentUser;
                Instance.WinHelper.InitializeProcessTimes(CreatedProcess, 0, false);
                Instance.WinHelper.WinProcesses.Add(CreatedProcess);
                return NTSTATUS.STATUS_SUCCESS;
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong ProcessHandlePtr = Instance.WinHelper.GetArg32(0);
                ulong DesiredAccess = Instance.WinHelper.GetArg32(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg32(2);
                ulong ParentProcess = Instance.WinHelper.GetArg32(3);
                ulong InheritObjectTable = Instance.WinHelper.GetArg32(4);
                ulong SectionHandle = Instance.WinHelper.GetArg32(5);
                ulong DebugPort = Instance.WinHelper.GetArg32(6);
                ulong TokenHandle = Instance.WinHelper.GetArg32(7);

                if (ProcessHandlePtr == 0)
                {
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if (DesiredAccess == 0)
                {
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if (ObjectAttributesPtr == 0)
                {
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if (!Instance.IsRegionMapped(ObjectAttributesPtr, 1))
                {
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }
                
                if (!StructSerializer.ParseStruct(Instance, ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 ObjectAttrs))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                WinProcess CreatedProcess = new WinProcess();
                CreatedProcess.Critical = false;
                CreatedProcess.Status = ProtectionStatus.None;
                CreatedProcess.Arch = BinaryArchitecture.x86;
                CreatedProcess.PPID = Instance.WinHelper.PID;
                //CreatedProcess.Name = Instance._emulator.ReadMemoryString(ObjectAttrs.ObjectName.Buffer, (int)ObjectAttrs.Length, Encoding.Unicode);
                uint NewPID = Instance.WinHelper.GenerateRandomPID();
                CreatedProcess.PID = NewPID;
                CreatedProcess.RunningUser = Instance.WinHelper.CurrentUser;
                Instance.WinHelper.InitializeProcessTimes(CreatedProcess, 0, false);
                Instance.WinHelper.WinProcesses.Add(CreatedProcess);
                WinHandle NewProcessHandle = Instance.WinHelper.OpenProcessHandle(NewPID, AccessMask.ProcessAllAccess);
                Instance.WinHelper.WinHandles.Add(NewProcessHandle);
                return NTSTATUS.STATUS_SUCCESS;
            }
            return Instance.WinUnimplemented;
        }
    }
}
