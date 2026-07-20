using System;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandle = Instance.WinHelper.GetArg(0);
                ulong JobObjectInformationClass = (uint)Instance.WinHelper.GetArg(1);
                ulong JobObjectInformation = Instance.WinHelper.GetArg(2);
                ulong JobObjectInformationLength = (uint)Instance.WinHelper.GetArg(3);
                return HandleSet(Instance, JobHandle, JobObjectInformationClass, JobObjectInformation, JobObjectInformationLength);
            }

            uint JobHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint JobObjectInformationClass32 = (uint)Instance.WinHelper.GetArg(1);
            uint JobObjectInformation32 = (uint)Instance.WinHelper.GetArg(2);
            uint JobObjectInformationLength32 = (uint)Instance.WinHelper.GetArg(3);
            return HandleSet(Instance, JobHandle32, JobObjectInformationClass32, JobObjectInformation32, JobObjectInformationLength32);
        }

        private static NTSTATUS HandleSet(BinaryEmulator Instance, ulong JobHandle, ulong JobObjectInformationClass, ulong JobObjectInformation, ulong JobObjectInformationLength)
        {
            if (JobHandle == 0)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Instance.WinHelper.HandleManager.HandleExists(JobHandle, HandleType.JobHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinJob Job = Instance.WinHelper.GetJobByHandle(JobHandle, AccessMask.GiveTemp);
            if (Job == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            JOBOBJECTINFOCLASS InfoClass = (JOBOBJECTINFOCLASS)JobObjectInformationClass;
            uint RequiredLength = GetRequiredLength(Instance, InfoClass, out NTSTATUS Status);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (JobObjectInformationLength < RequiredLength)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (JobObjectInformation == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(JobObjectInformation, RequiredLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Data = Instance.WinHelper.ReadMemorySpan(JobObjectInformation, RequiredLength);
            if (Data.Length < RequiredLength)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            switch (InfoClass)
            {
                case JOBOBJECTINFOCLASS.JobObjectBasicLimitInformation:
                    return SetBasicLimitInformation(Instance, Job, Data);
                case JOBOBJECTINFOCLASS.JobObjectBasicUIRestrictions:
                    Job.UiRestrictionsClass = ReadUInt32(Data, 0x00);
                    return NTSTATUS.STATUS_SUCCESS;
                case JOBOBJECTINFOCLASS.JobObjectEndOfJobTimeInformation:
                    Job.EndOfJobTimeAction = ReadUInt32(Data, 0x00);
                    return NTSTATUS.STATUS_SUCCESS;
                case JOBOBJECTINFOCLASS.JobObjectAssociateCompletionPortInformation:
                    return SetAssociateCompletionPortInformation(Instance, Job, Data);
                case JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation:
                    return SetExtendedLimitInformation(Instance, Job, Data);
                case JOBOBJECTINFOCLASS.JobObjectNotificationLimitInformation:
                    return SetNotificationLimitInformation(Job, Data);
                case JOBOBJECTINFOCLASS.JobObjectCpuRateControlInformation:
                    return SetCpuRateControlInformation(Job, Data);
                case JOBOBJECTINFOCLASS.JobObjectNetRateControlInformation:
                    return SetNetRateControlInformation(Job, Data);
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

        private static uint GetRequiredLength(BinaryEmulator Instance, JOBOBJECTINFOCLASS InfoClass, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;

            switch (InfoClass)
            {
                case JOBOBJECTINFOCLASS.JobObjectBasicLimitInformation:
                    return Instance._binary.Architecture == BinaryArchitecture.x64 ? 0x40u : 0x2Cu;
                case JOBOBJECTINFOCLASS.JobObjectBasicUIRestrictions:
                case JOBOBJECTINFOCLASS.JobObjectEndOfJobTimeInformation:
                    return 0x04;
                case JOBOBJECTINFOCLASS.JobObjectAssociateCompletionPortInformation:
                    return Instance._binary.Architecture == BinaryArchitecture.x64 ? 0x10u : 0x08u;
                case JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation:
                    return Instance._binary.Architecture == BinaryArchitecture.x64 ? 0x90u : 0x6Cu;
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

        private static NTSTATUS SetBasicLimitInformation(BinaryEmulator Instance, WinJob Job, Span<byte> Data)
        {
            bool IsX64 = Instance._binary.Architecture == BinaryArchitecture.x64;
            Job.PerProcessUserTimeLimit = ReadUInt64(Data, 0x00);
            Job.PerJobUserTimeLimit = ReadUInt64(Data, 0x08);
            Job.LimitFlags = ReadUInt32(Data, 0x10);

            if (IsX64)
            {
                Job.MinimumWorkingSetSize = ReadUInt64(Data, 0x18);
                Job.MaximumWorkingSetSize = ReadUInt64(Data, 0x20);
                Job.ActiveProcessLimit = ReadUInt32(Data, 0x28);
                Job.Affinity = ReadUInt64(Data, 0x30);
                Job.PriorityClass = ReadUInt32(Data, 0x38);
                Job.SchedulingClass = ReadUInt32(Data, 0x3C);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Job.MinimumWorkingSetSize = ReadUInt32(Data, 0x14);
            Job.MaximumWorkingSetSize = ReadUInt32(Data, 0x18);
            Job.ActiveProcessLimit = ReadUInt32(Data, 0x1C);
            Job.Affinity = ReadUInt32(Data, 0x20);
            Job.PriorityClass = ReadUInt32(Data, 0x24);
            Job.SchedulingClass = ReadUInt32(Data, 0x28);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS SetAssociateCompletionPortInformation(BinaryEmulator Instance, WinJob Job, Span<byte> Data)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Job.CompletionKey = ReadUInt64(Data, 0x00);
                Job.CompletionPort = ReadUInt64(Data, 0x08);
            }
            else
            {
                Job.CompletionKey = ReadUInt32(Data, 0x00);
                Job.CompletionPort = ReadUInt32(Data, 0x04);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS SetExtendedLimitInformation(BinaryEmulator Instance, WinJob Job, Span<byte> Data)
        {
            NTSTATUS Status = SetBasicLimitInformation(Instance, Job, Data);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Job.ProcessMemoryLimit = ReadUInt64(Data, 0x70);
                Job.JobMemoryLimit = ReadUInt64(Data, 0x78);
                Job.PeakProcessMemoryUsed = ReadUInt64(Data, 0x80);
                Job.PeakJobMemoryUsed = ReadUInt64(Data, 0x88);
            }
            else
            {
                Job.ProcessMemoryLimit = ReadUInt32(Data, 0x5C);
                Job.JobMemoryLimit = ReadUInt32(Data, 0x60);
                Job.PeakProcessMemoryUsed = ReadUInt32(Data, 0x64);
                Job.PeakJobMemoryUsed = ReadUInt32(Data, 0x68);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS SetNotificationLimitInformation(WinJob Job, Span<byte> Data)
        {
            Job.IoReadBytesLimit = ReadUInt64(Data, 0x00);
            Job.IoWriteBytesLimit = ReadUInt64(Data, 0x08);
            Job.NotificationPerJobUserTimeLimit = ReadUInt64(Data, 0x10);
            Job.NotificationJobMemoryLimit = ReadUInt64(Data, 0x18);
            Job.NotificationRateControlTolerance = ReadUInt32(Data, 0x20);
            Job.NotificationRateControlToleranceInterval = ReadUInt32(Data, 0x24);
            Job.NotificationLimitFlags = ReadUInt32(Data, 0x28);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS SetCpuRateControlInformation(WinJob Job, Span<byte> Data)
        {
            Job.CpuRateControlFlags = ReadUInt32(Data, 0x00);

            if ((Job.CpuRateControlFlags & 0x10) != 0)
            {
                Job.CpuRateControlMinRate = (ushort)ReadUInt16(Data, 0x04);
                Job.CpuRateControlMaxRate = (ushort)ReadUInt16(Data, 0x06);
                Job.CpuRateControlValue = 0;
                Job.CpuRateControlWeight = 0;
            }
            else if ((Job.CpuRateControlFlags & 0x2) != 0)
            {
                Job.CpuRateControlWeight = ReadUInt32(Data, 0x04);
                Job.CpuRateControlValue = 0;
                Job.CpuRateControlMinRate = 0;
                Job.CpuRateControlMaxRate = 0;
            }
            else
            {
                Job.CpuRateControlValue = ReadUInt32(Data, 0x04);
                Job.CpuRateControlWeight = 0;
                Job.CpuRateControlMinRate = 0;
                Job.CpuRateControlMaxRate = 0;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS SetNetRateControlInformation(WinJob Job, Span<byte> Data)
        {
            Job.NetRateControlMaxBandwidth = ReadUInt64(Data, 0x00);
            Job.NetRateControlFlags = ReadUInt32(Data, 0x08);
            Job.NetRateControlDscpTag = Data[0x0C];
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint ReadUInt32(Span<byte> Data, int Offset)
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(Data.Slice(Offset, 4));
        }

        private static ulong ReadUInt64(Span<byte> Data, int Offset)
        {
            return BinaryPrimitives.ReadUInt64LittleEndian(Data.Slice(Offset, 8));
        }

        private static ushort ReadUInt16(Span<byte> Data, int Offset)
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(Data.Slice(Offset, 2));
        }
    }
}
