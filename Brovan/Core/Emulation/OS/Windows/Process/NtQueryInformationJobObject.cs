using System;
using System.Buffers.Binary;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandle = Instance.WinHelper.GetArg(0);
                ulong JobObjectInformationClass = (uint)Instance.WinHelper.GetArg(1);
                ulong JobObjectInformation = Instance.WinHelper.GetArg(2);
                ulong JobObjectInformationLength = (uint)Instance.WinHelper.GetArg(3);
                ulong ReturnLength = Instance.WinHelper.GetArg(4);
                return HandleQuery(Instance, JobHandle, JobObjectInformationClass, JobObjectInformation, JobObjectInformationLength, ReturnLength);
            }

            uint JobHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint JobObjectInformationClass32 = (uint)Instance.WinHelper.GetArg(1);
            uint JobObjectInformation32 = (uint)Instance.WinHelper.GetArg(2);
            uint JobObjectInformationLength32 = (uint)Instance.WinHelper.GetArg(3);
            uint ReturnLength32 = (uint)Instance.WinHelper.GetArg(4);
            return HandleQuery(Instance, JobHandle32, JobObjectInformationClass32, JobObjectInformation32, JobObjectInformationLength32, ReturnLength32);
        }

        private static NTSTATUS HandleQuery(BinaryEmulator Instance, ulong JobHandle, ulong JobObjectInformationClass, ulong JobObjectInformation, ulong JobObjectInformationLength, ulong ReturnLength)
        {
            NTSTATUS ResolveStatus = ResolveJob(Instance, JobHandle, out WinJob Job);
            if (ResolveStatus != NTSTATUS.STATUS_SUCCESS)
                return ResolveStatus;

            if (JobObjectInformationLength > uint.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            JOBOBJECTINFOCLASS InfoClass = (JOBOBJECTINFOCLASS)JobObjectInformationClass;
            uint RequiredLength = GetRequiredLength(Instance, Job, InfoClass, out NTSTATUS Status);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (ReturnLength != 0)
            {
                if (!Instance.IsRegionMapped(ReturnLength, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (JobObjectInformationLength < RequiredLength)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (JobObjectInformation == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(JobObjectInformation, RequiredLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            switch (InfoClass)
            {
                case JOBOBJECTINFOCLASS.JobObjectBasicAccountingInformation:
                    return WriteBasicAccountingInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectBasicAndIoAccountingInformation:
                    return WriteBasicAndIoAccountingInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectBasicLimitInformation:
                    return WriteBasicLimitInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectBasicProcessIdList:
                    return WriteBasicProcessIdList(Instance, Job, JobObjectInformation, (uint)JobObjectInformationLength);
                case JOBOBJECTINFOCLASS.JobObjectBasicUIRestrictions:
                    return WriteUInt32Value(Instance, JobObjectInformation, Job.UiRestrictionsClass);
                case JOBOBJECTINFOCLASS.JobObjectEndOfJobTimeInformation:
                    return WriteUInt32Value(Instance, JobObjectInformation, Job.EndOfJobTimeAction);
                case JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation:
                    return WriteExtendedLimitInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectNotificationLimitInformation:
                    return WriteNotificationLimitInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectCpuRateControlInformation:
                    return WriteCpuRateControlInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectNetRateControlInformation:
                    return WriteNetRateControlInformation(Instance, Job, JobObjectInformation);
                case JOBOBJECTINFOCLASS.JobObjectGroupInformation:
                case JOBOBJECTINFOCLASS.JobObjectGroupInformationEx:
                case JOBOBJECTINFOCLASS.JobObjectLimitViolationInformation:
                case JOBOBJECTINFOCLASS.JobObjectLimitViolationInformation2:
                case JOBOBJECTINFOCLASS.JobObjectNotificationLimitInformation2:
                case JOBOBJECTINFOCLASS.JobObjectReserved1Information:
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                default:
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }

        private static NTSTATUS ResolveJob(BinaryEmulator Instance, ulong JobHandle, out WinJob Job)
        {
            Job = null;

            if (JobHandle == 0)
            {
                Job = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID)?.Job;
                return Job != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (!Instance.WinHelper.HandleManager.HandleExists(JobHandle, HandleType.JobHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Job = Instance.WinHelper.GetJobByHandle(JobHandle, AccessMask.GiveTemp);
            return Job != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
        }

        private static uint GetRequiredLength(BinaryEmulator Instance, WinJob Job, JOBOBJECTINFOCLASS InfoClass, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;

            switch (InfoClass)
            {
                case JOBOBJECTINFOCLASS.JobObjectBasicAccountingInformation:
                    return 0x30;
                case JOBOBJECTINFOCLASS.JobObjectBasicAndIoAccountingInformation:
                    return 0x60;
                // The LARGE_INTEGER limits align the x86 records to 8 bytes.
                case JOBOBJECTINFOCLASS.JobObjectBasicLimitInformation:
                    return Instance._binary.Architecture == BinaryArchitecture.x64 ? 0x40u : 0x30u;
                case JOBOBJECTINFOCLASS.JobObjectBasicProcessIdList:
                    return 8u + (uint)Instance.WinHelper.PointerSize;
                case JOBOBJECTINFOCLASS.JobObjectBasicUIRestrictions:
                    return 0x04;
                case JOBOBJECTINFOCLASS.JobObjectEndOfJobTimeInformation:
                    return 0x04;
                case JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation:
                    return Instance._binary.Architecture == BinaryArchitecture.x64 ? 0x90u : 0x70u;
                case JOBOBJECTINFOCLASS.JobObjectNotificationLimitInformation:
                    return 0x2C;
                case JOBOBJECTINFOCLASS.JobObjectCpuRateControlInformation:
                    return 0x08;
                case JOBOBJECTINFOCLASS.JobObjectNetRateControlInformation:
                    return 0x10;
                case JOBOBJECTINFOCLASS.JobObjectGroupInformation:
                case JOBOBJECTINFOCLASS.JobObjectGroupInformationEx:
                case JOBOBJECTINFOCLASS.JobObjectLimitViolationInformation:
                case JOBOBJECTINFOCLASS.JobObjectLimitViolationInformation2:
                case JOBOBJECTINFOCLASS.JobObjectNotificationLimitInformation2:
                case JOBOBJECTINFOCLASS.JobObjectReserved1Information:
                    Status = NTSTATUS.STATUS_NOT_SUPPORTED;
                    return 0;
                default:
                    Status = NTSTATUS.STATUS_INVALID_INFO_CLASS;
                    return 0;
            }
        }

        private static NTSTATUS WriteUInt32Value(BinaryEmulator Instance, ulong Address, uint Value)
        {
            Span<byte> Buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer, Value);
            return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS WriteBasicAccountingInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            Span<byte> Buffer = stackalloc byte[0x30];
            if (!TryWriteBasicAccounting(Instance, Job, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS WriteBasicAndIoAccountingInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            Span<byte> Buffer = stackalloc byte[0x60];
            Buffer.Clear();
            if (!TryWriteBasicAccounting(Instance, Job, Buffer.Slice(0x00, 0x30)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // IO_COUNTERS is intentionally zeroed for now.
            return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static bool TryWriteBasicAccounting(BinaryEmulator Instance, WinJob Job, Span<byte> Buffer)
        {
            ulong TotalUserTime = 0;
            ulong TotalKernelTime = 0;
            uint TotalProcesses = 0;
            uint ActiveProcesses = 0;

            foreach (uint ProcessId in Job.ProcessIds)
            {
                TotalProcesses++;
                WinProcess Process = Instance.WinHelper.WinProcesses.FirstOrDefault(P => P.PID == ProcessId);
                if (Process == null)
                    continue;

                Instance.WinHelper.UpdateProcessTimes(Process);
                TotalUserTime += (ulong)Process.UserTime;
                TotalKernelTime += (ulong)Process.KernelTime;
                if (WinSysHelper.IsProcessAlive(Process))
                    ActiveProcesses++;
            }

            // NT counts only processes a limit violation ended, and job limits are not enforced.
            const uint TotalTerminatedProcesses = 0;

            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), TotalUserTime);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), TotalKernelTime);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), TotalUserTime);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), TotalKernelTime);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x20, 4), 0);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x24, 4), TotalProcesses);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), ActiveProcesses);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x2C, 4), TotalTerminatedProcesses);
            return true;
        }

        private static NTSTATUS WriteBasicLimitInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Span<byte> Buffer = stackalloc byte[0x40];
                WriteBasicLimitInformationToSpan(Job, Buffer);
                return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Span<byte> Buffer32 = stackalloc byte[0x30];
            Buffer32.Clear();
            WriteBasicLimitInformationToSpan(Job, Buffer32);
            return Instance._emulator.WriteMemory(Address, Buffer32) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static void WriteBasicLimitInformationToSpan(WinJob Job, Span<byte> Buffer)
        {
            bool IsX64 = Buffer.Length == 0x40;
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Job.PerProcessUserTimeLimit);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), Job.PerJobUserTimeLimit);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10, 4), Job.LimitFlags);

            if (IsX64)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), Job.MinimumWorkingSetSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x20, 8), Job.MaximumWorkingSetSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), Job.ActiveProcessLimit);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x30, 8), Job.Affinity);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x38, 4), Job.PriorityClass);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x3C, 4), Job.SchedulingClass);
                return;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14, 4), (uint)Job.MinimumWorkingSetSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), (uint)Job.MaximumWorkingSetSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x1C, 4), Job.ActiveProcessLimit);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x20, 4), (uint)Job.Affinity);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x24, 4), Job.PriorityClass);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), Job.SchedulingClass);
        }

        // The WOW64 thunk copies nothing back on STATUS_BUFFER_OVERFLOW.
        private static NTSTATUS WriteBasicProcessIdList(BinaryEmulator Instance, WinJob Job, ulong Address, uint Length)
        {
            uint PtrSize = (uint)Instance.WinHelper.PointerSize;

            uint Live = 0;
            foreach (uint ProcessId in Job.ProcessIds)
            {
                if (IsMemberAlive(Instance, ProcessId))
                    Live++;
            }

            uint Fit = Math.Min(Live, (Length - 8) / PtrSize);
            bool Overflow = Fit < Live;
            if (Overflow && PtrSize == 4)
                return NTSTATUS.STATUS_BUFFER_OVERFLOW;

            uint Size = 8 + Fit * PtrSize;
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Size);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), Live);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Fit);

            int Offset = 0x08;
            uint Written = 0;
            foreach (uint ProcessId in Job.ProcessIds)
            {
                if (Written == Fit)
                    break;

                if (!IsMemberAlive(Instance, ProcessId))
                    continue;

                if (PtrSize == 8)
                    BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), ProcessId);
                else
                    BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), ProcessId);

                Offset += (int)PtrSize;
                Written++;
            }

            if (!Instance._emulator.WriteMemory(Address, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Overflow ? NTSTATUS.STATUS_BUFFER_OVERFLOW : NTSTATUS.STATUS_SUCCESS;
        }

        private static bool IsMemberAlive(BinaryEmulator Instance, uint ProcessId)
        {
            return WinSysHelper.IsProcessAlive(Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == ProcessId));
        }

        private static NTSTATUS WriteExtendedLimitInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Span<byte> Buffer = stackalloc byte[0x90];
                Buffer.Clear();
                WriteBasicLimitInformationToSpan(Job, Buffer.Slice(0x00, 0x40));
                // IO_COUNTERS block is intentionally zeroed.
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x70, 8), Job.ProcessMemoryLimit);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x78, 8), Job.JobMemoryLimit);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x80, 8), Job.PeakProcessMemoryUsed);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x88, 8), Job.PeakJobMemoryUsed);
                return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            Span<byte> Buffer32 = stackalloc byte[0x70];
            Buffer32.Clear();
            WriteBasicLimitInformationToSpan(Job, Buffer32.Slice(0x00, 0x30));
            // IO_COUNTERS block is intentionally zeroed.
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer32.Slice(0x60, 4), (uint)Job.ProcessMemoryLimit);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer32.Slice(0x64, 4), (uint)Job.JobMemoryLimit);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer32.Slice(0x68, 4), (uint)Job.PeakProcessMemoryUsed);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer32.Slice(0x6C, 4), (uint)Job.PeakJobMemoryUsed);
            return Instance._emulator.WriteMemory(Address, Buffer32) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS WriteNotificationLimitInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            Span<byte> Buffer = stackalloc byte[0x2C];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Job.IoReadBytesLimit);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), Job.IoWriteBytesLimit);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), Job.NotificationPerJobUserTimeLimit);
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), Job.NotificationJobMemoryLimit);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x20, 4), Job.NotificationRateControlTolerance);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x24, 4), Job.NotificationRateControlToleranceInterval);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), Job.NotificationLimitFlags);
            return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS WriteCpuRateControlInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            Span<byte> Buffer = stackalloc byte[0x08];
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), Job.CpuRateControlFlags);

            if ((Job.CpuRateControlFlags & 0x10) != 0)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x04, 2), Job.CpuRateControlMinRate);
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0x06, 2), Job.CpuRateControlMaxRate);
            }
            else if ((Job.CpuRateControlFlags & 0x2) != 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Job.CpuRateControlWeight);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), Job.CpuRateControlValue);
            }

            return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static NTSTATUS WriteNetRateControlInformation(BinaryEmulator Instance, WinJob Job, ulong Address)
        {
            Span<byte> Buffer = stackalloc byte[0x10];
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), Job.NetRateControlMaxBandwidth);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), Job.NetRateControlFlags);
            Buffer[0x0C] = Job.NetRateControlDscpTag;
            return Instance._emulator.WriteMemory(Address, Buffer) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
