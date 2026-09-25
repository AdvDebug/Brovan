using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationProcess : IWinSyscall
    {
        // MEM_EXECUTE_OPTION_DISABLE | DISABLE_THUNK_EMULATION | PERMANENT.
        private const uint MemExecuteOptionsDepOn = 0xD;
        private const uint MemExecuteOptionEnable = 0x2;
        private const ushort DllCharacteristicsNxCompat = 0x0100;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.WinHelper.GetArg(1);
                ulong OutBufferPtr = Instance.WinHelper.GetArg(2);
                uint OutBufferLength = (uint)Instance.WinHelper.GetArg(3);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg(4);
                void SetReturnLength(uint Len)
                {
                    if (ReturnLengthPtr == 0)
                        return;
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return;
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Len);
                }

                bool Wide = Instance.WinHelper.PointerSize == 8;

                NTSTATUS WriteExact(Span<byte> Record, uint ReportedLength)
                {
                    if (OutBufferLength != (uint)Record.Length)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (OutBufferPtr == 0 || !Instance.WriteMemory(OutBufferPtr, Record))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    SetReturnLength(ReportedLength);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                bool FullQueryRight = InfoClass == PROCESSINFOCLASS.ProcessDebugPort ||
                                      InfoClass == PROCESSINFOCLASS.ProcessDebugObjectHandle ||
                                      InfoClass == PROCESSINFOCLASS.ProcessDebugFlags;

                NTSTATUS ResolveStatus = Instance.WinHelper.ResolveProcessHandle(ProcessHandle,
                    FullQueryRight ? AccessMask.ProcessQueryInformation : AccessMask.ProcessQueryLimitedInformation, out WinProcess Process);
                if (ResolveStatus != NTSTATUS.STATUS_SUCCESS)
                    return ResolveStatus;

                bool Own = Process.PID == Instance.WinHelper.PID;

                switch (InfoClass)
                {
                    // GlobalMemoryStatusEx reads PagefileLimit here and takes all-ones as no quota.
                    case PROCESSINFOCLASS.ProcessQuotaLimits:
                    {
                        uint QuotaSize = Wide ? 0x30u : 0x20u;

                        if (OutBufferLength < QuotaSize)
                        {
                            SetReturnLength(QuotaSize);
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (!Instance.IsRegionMapped(OutBufferPtr, QuotaSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        Span<byte> Quota = Instance.WinHelper.Shared.GetSpan(QuotaSize);
                        Quota.Clear();

                        ulong NoLimit = Wide ? ulong.MaxValue : uint.MaxValue;
                        ulong WorkingSetMinimum = 200 * 4096;
                        ulong WorkingSetMaximum = 1380 * 4096;

                        if (Wide)
                        {
                            BinaryPrimitives.WriteUInt64LittleEndian(Quota.Slice(0x00), NoLimit);
                            BinaryPrimitives.WriteUInt64LittleEndian(Quota.Slice(0x08), NoLimit);
                            BinaryPrimitives.WriteUInt64LittleEndian(Quota.Slice(0x10), WorkingSetMinimum);
                            BinaryPrimitives.WriteUInt64LittleEndian(Quota.Slice(0x18), WorkingSetMaximum);
                            BinaryPrimitives.WriteUInt64LittleEndian(Quota.Slice(0x20), NoLimit);
                        }
                        else
                        {
                            BinaryPrimitives.WriteUInt32LittleEndian(Quota.Slice(0x00), (uint)NoLimit);
                            BinaryPrimitives.WriteUInt32LittleEndian(Quota.Slice(0x04), (uint)NoLimit);
                            BinaryPrimitives.WriteUInt32LittleEndian(Quota.Slice(0x08), (uint)WorkingSetMinimum);
                            BinaryPrimitives.WriteUInt32LittleEndian(Quota.Slice(0x0C), (uint)WorkingSetMaximum);
                            BinaryPrimitives.WriteUInt32LittleEndian(Quota.Slice(0x10), (uint)NoLimit);
                        }

                        if (!Instance._emulator.WriteMemory(OutBufferPtr, Quota))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        SetReturnLength(QuotaSize);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                    case PROCESSINFOCLASS.ProcessIoCounters:
                    {
                        Span<byte> Counters = stackalloc byte[0x30];
                        Counters.Clear();
                        return WriteExact(Counters, 0x30);
                    }

                    case PROCESSINFOCLASS.ProcessVmCounters:
                        return QueryVmCounters(Instance, Own, OutBufferPtr, OutBufferLength, SetReturnLength);

                    case PROCESSINFOCLASS.ProcessBasicInformation:
                        return QueryBasicInformation(Instance, Process, Own, OutBufferPtr, OutBufferLength, SetReturnLength);

                    case PROCESSINFOCLASS.ProcessTimes:
                        {
                            NTSTATUS Status = QueryProcessTimes(Instance, Process, OutBufferPtr, OutBufferLength, SetReturnLength);
                            if (Status == NTSTATUS.STATUS_SUCCESS)
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessTimes.", LogFlags.Syscall);
                            return Status;
                        }

                    case PROCESSINFOCLASS.ProcessPriorityClass:
                        {
                            // PROCESS_PRIORITY_CLASS: Foreground, PriorityClass.
                            Span<byte> Priority = stackalloc byte[2];
                            Priority[0] = 0;
                            Priority[1] = Process.PriorityClass;
                            return WriteExact(Priority, 2);
                        }

                    case PROCESSINFOCLASS.ProcessHandleCount:
                        {
                            // NT reports 4 bytes for PROCESS_HANDLE_INFORMATION too.
                            uint Count = Own ? (uint)Instance.WinHelper.HandleManager.Count : 0u;
                            if (OutBufferLength != 4 && OutBufferLength != 8)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            Span<byte> Handles = stackalloc byte[8];
                            BinaryPrimitives.WriteUInt32LittleEndian(Handles.Slice(0, 4), Count);
                            BinaryPrimitives.WriteUInt32LittleEndian(Handles.Slice(4, 4), Count);
                            if (!Instance.WriteMemory(OutBufferPtr, Handles.Slice(0, (int)OutBufferLength)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(4);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessAffinityMask:
                        {
                            // WOW64 does not thunk this class. 16 bytes is a GROUP_AFFINITY.
                            if (!Wide)
                                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

                            if (OutBufferLength != 8 && OutBufferLength != 16)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            Span<byte> Affinity = stackalloc byte[16];
                            Affinity.Clear();
                            BinaryPrimitives.WriteUInt64LittleEndian(Affinity, Own ? Instance.WinHelper.ProcessAffinityMask : Instance.WinHelper.ActiveProcessorMask);
                            return WriteExact(Affinity.Slice(0, (int)OutBufferLength), OutBufferLength);
                        }

                    case PROCESSINFOCLASS.ProcessSessionInformation:
                        {
                            Span<byte> Session = stackalloc byte[4];
                            BinaryPrimitives.WriteUInt32LittleEndian(Session, SessionIdOf(Instance, Process));
                            return WriteExact(Session, 4);
                        }

                    case PROCESSINFOCLASS.ProcessBreakOnTermination:
                        {
                            Span<byte> Critical = stackalloc byte[4];
                            BinaryPrimitives.WriteUInt32LittleEndian(Critical, Process.Critical ? 1u : 0u);
                            NTSTATUS Status = WriteExact(Critical, 4);
                            if (Status == NTSTATUS.STATUS_SUCCESS && (Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessBreakOnTermination for \"{Process.Name}\".", LogFlags.Syscall);
                            return Status;
                        }

                    case PROCESSINFOCLASS.ProcessDebugFlags:
                        {
                            Span<byte> Flags = stackalloc byte[4];
                            BinaryPrimitives.WriteUInt32LittleEndian(Flags, Own ? Instance.WinHelper.ProcessDebugFlags : 1u);
                            return WriteExact(Flags, 4);
                        }

                    case PROCESSINFOCLASS.ProcessCycleTime:
                        {
                            Instance.WinHelper.UpdateProcessTimes(Process);

                            Span<byte> Cycles = stackalloc byte[0x10];
                            Cycles.Clear();
                            BinaryPrimitives.WriteUInt64LittleEndian(Cycles, WinSysHelper.TimeToCycles(Process.UserTime + Process.KernelTime));
                            return WriteExact(Cycles, 0x10);
                        }

                    case PROCESSINFOCLASS.ProcessExecuteFlags:
                        {
                            if (!Own)
                                return NTSTATUS.STATUS_INVALID_PARAMETER;

                            if (OutBufferLength < sizeof(uint))
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, sizeof(uint)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            ushort DllCharacteristics = Wide
                                ? Instance._binary.PE.OptionalHeader64.DllCharacteristics
                                : Instance._binary.PE.OptionalHeader32.DllCharacteristics;
                            uint ExecuteFlags = Wide || (DllCharacteristics & DllCharacteristicsNxCompat) != 0 ? MemExecuteOptionsDepOn : MemExecuteOptionEnable;

                            if (!Instance.WinHelper.WriteUInt32(OutBufferPtr, ExecuteFlags))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(sizeof(uint));
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDefaultHardErrorMode:
                        {
                            if (OutBufferLength < sizeof(uint))
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, sizeof(uint)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance.WinHelper.WriteUInt32(OutBufferPtr, Own ? Instance.WinHelper.DefaultHardErrorMode : 1u))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(sizeof(uint));
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDebugPort:
                        {
                            if (OutBufferLength < (ulong)Instance.WinHelper.PointerSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, (uint)Instance.WinHelper.PointerSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried debug port for process \"{Process.Name}\".", LogFlags.Syscall);
                            SetReturnLength((uint)Instance.WinHelper.PointerSize);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDebugObjectHandle:
                        {
                            if (OutBufferLength != (uint)Instance.WinHelper.PointerSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, (uint)Instance.WinHelper.PointerSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried debug object handle for process \"{Process.Name}\".", LogFlags.Syscall);
                            SetReturnLength((uint)Instance.WinHelper.PointerSize);
                            return NTSTATUS.STATUS_PORT_NOT_SET;
                        }
                    case PROCESSINFOCLASS.ProcessWow64Information:
                        {
                            if (OutBufferLength < (ulong)Instance.WinHelper.PointerSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            ulong Wow64Peb = 0;
                            if (Own)
                                Wow64Peb = Wide ? 0UL : Instance.PEB;
                            else if (Process.Arch == BinaryArchitecture.x86)
                                Wow64Peb = Process.Remote?.PebAddress ?? Instance.PEB;

                            if (!Instance.WinHelper.WritePointer(OutBufferPtr, Wow64Peb))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried Wow64 status of process \"{Process.Name}\".", LogFlags.Syscall);
                            SetReturnLength((uint)Instance.WinHelper.PointerSize);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessImageFileName:
                        return QueryImageFileName(Instance, Process, Own, false, OutBufferPtr, OutBufferLength, SetReturnLength);
                    case PROCESSINFOCLASS.ProcessImageFileNameWin32:
                        return QueryImageFileName(Instance, Process, Own, true, OutBufferPtr, OutBufferLength, SetReturnLength);
                    case PROCESSINFOCLASS.ProcessCookie:
                        {
                            if (!Own)
                                return NTSTATUS.STATUS_INVALID_PARAMETER;

                            if (OutBufferLength < 4)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (Instance.ProcessCookie == 0)
                            {
                                Instance.ProcessCookie = (uint)Random.Shared.NextInt64();
                                if (Instance.ProcessCookie == 0)
                                    Instance.ProcessCookie = 1;
                            }

                            if (!Instance._emulator.WriteMemory(OutBufferPtr, Instance.ProcessCookie, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(4);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessCookie = 0x{Instance.ProcessCookie:X}.", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessImageInformation:
                        {
                            uint StructSize = SECTION_IMAGE_INFORMATION.SizeOf(Wide);

                            if (OutBufferLength < StructSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SECTION_IMAGE_INFORMATION Information;
                            if (Own)
                                Information = BuildOwnImageInformation(Instance, Wide);
                            else if (Process.ImageInformation.HasValue)
                                Information = Process.ImageInformation.Value;
                            else
                                return NTSTATUS.STATUS_NOT_SUPPORTED;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            Information.WriteTo(Buffer, Wide);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(StructSize);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessImageInformation (TransferAddress=0x{Information.TransferAddress:X}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDeviceMap:
                        {
                            // PROCESS_DEVICEMAP_INFORMATION: drive bitmask, then one DRIVE_* byte per letter. 0x24 bytes on both architectures.
                            const uint StructSize = 0x24;
                            const byte DriveFixed = 3;

                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint Map = Instance.WinHelper.DriveMap;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            Buffer.Clear();
                            WriteUInt32(Buffer, 0, Map);

                            for (int Index = 0; Index < 26; Index++)
                            {
                                if ((Map & (1u << Index)) != 0)
                                    Buffer[4 + Index] = DriveFixed;
                            }

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(StructSize);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case (PROCESSINFOCLASS)52:
                        {
                            // PROCESS_MITIGATION_POLICY_INFORMATION: policy id in, policy value out. 8 bytes on both architectures.
                            const uint StructSize = 8;

                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint Policy = Instance.ReadMemoryUInt(OutBufferPtr);

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            WriteUInt32(Buffer, 0, Policy);

                            uint PolicyValue = Policy == 0 ? 1u : 0u;

                            WriteUInt32(Buffer, 4, PolicyValue);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(StructSize);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: ProcessMitigationPolicy ({Policy})", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    default:
                        Helpers.Utils.PrintHighlight($"[!] NtQueryInformationProcess: InfoClass 0x{InfoClass:X} is not implemented");
                        return Instance.WinUnimplemented;
                }
            }
        }

        // The WOW64 thunk copies every field but BasePriority.
        private static NTSTATUS QueryBasicInformation(BinaryEmulator Instance, WinProcess Process, bool Own, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            const uint FlagIsProtectedProcess = 0x1;
            const uint FlagIsWow64Process = 0x2;
            const uint FlagIsProcessDeleting = 0x4;

            bool Wide = Instance.WinHelper.PointerSize == 8;
            uint BasicSize = Wide ? 0x30u : 0x18u;
            uint ExtendedSize = Wide ? 0x40u : 0x20u;

            if (OutBufferLength != BasicSize && OutBufferLength != ExtendedSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, OutBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool Extended = OutBufferLength == ExtendedSize;
            ulong Peb = Instance.PEB;
            uint ExitStatus = Own ? (uint)NTSTATUS.STATUS_PENDING : Process.ExitStatus;

            if (!Own && Process.Remote != null)
            {
                if (Process.Remote.PebAddress != 0)
                    Peb = Process.Remote.PebAddress;

                if (Process.Remote.HasExited)
                    ExitStatus = Process.Remote.ExitCode;
            }

            uint BasePriority = Own ? Instance.WinHelper.CurrentPriority : WinSysHelper.PriorityClassBase(Process.PriorityClass);
            ulong Affinity = Own ? Instance.WinHelper.ProcessAffinityMask : Instance.WinHelper.ActiveProcessorMask;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(OutBufferLength);
            if (!Instance._emulator.ReadMemory(OutBufferPtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            int Basic = Extended ? (Wide ? 8 : 4) : 0;

            if (Wide)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Basic + 0x00, 8), ExitStatus);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Basic + 0x08, 8), Peb);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Basic + 0x10, 8), Affinity);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Basic + 0x18, 8), BasePriority);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Basic + 0x20, 8), Process.PID);
                BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Basic + 0x28, 8), Process.PPID);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Basic + 0x00, 4), ExitStatus);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Basic + 0x04, 4), (uint)Peb);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Basic + 0x08, 4), (uint)Affinity);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Basic + 0x10, 4), Process.PID);
                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Basic + 0x14, 4), Process.PPID);
            }

            if (Extended)
            {
                uint Flags = 0;
                if (Instance.WinHelper.IsProtectedStatus(Process.Status))
                    Flags |= FlagIsProtectedProcess;
                if (Process.Arch == BinaryArchitecture.x86 || (Own && !Wide))
                    Flags |= FlagIsWow64Process;
                if (!WinSysHelper.IsProcessAlive(Process))
                    Flags |= FlagIsProcessDeleting;

                if (Wide)
                    BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x00, 8), ExtendedSize);
                else
                    BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), ExtendedSize);

                BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice((int)ExtendedSize - (Wide ? 8 : 4), 4), Flags);
            }

            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            SetReturnLength(OutBufferLength);
            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried PROCESS_BASIC_INFORMATION of process \"{Process.Name}\" (PID={Process.PID}).", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // Another process's memory is not visible from this emulator.
        private static NTSTATUS QueryVmCounters(BinaryEmulator Instance, bool Own, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            bool Wide = Instance.WinHelper.PointerSize == 8;
            uint Size = Wide ? 0x58u : 0x2Cu;
            uint SizeEx = Wide ? 0x60u : 0x30u;
            uint SizeEx2 = Wide ? 0x70u : 0x40u;

            if (OutBufferLength != Size && OutBufferLength != SizeEx && OutBufferLength != SizeEx2)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, OutBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong VirtualSize = 0;
            ulong CommittedSize = 0;
            if (Own)
                Instance.SumGuestMemoryUsage(out VirtualSize, out CommittedSize);

            Span<byte> Counters = Instance.WinHelper.Shared.GetSpan(OutBufferLength);
            Counters.Clear();

            if (Wide)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x00), VirtualSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x08), VirtualSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x18), CommittedSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x20), CommittedSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x48), CommittedSize);
                BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x50), CommittedSize);
                if (OutBufferLength >= SizeEx)
                    BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x58), CommittedSize);
                if (OutBufferLength >= SizeEx2)
                    BinaryPrimitives.WriteUInt64LittleEndian(Counters.Slice(0x60), CommittedSize);
            }
            else
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x00), (uint)VirtualSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x04), (uint)VirtualSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x0C), (uint)CommittedSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x10), (uint)CommittedSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x24), (uint)CommittedSize);
                BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x28), (uint)CommittedSize);
                if (OutBufferLength >= SizeEx)
                    BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x2C), (uint)CommittedSize);
                if (OutBufferLength >= SizeEx2)
                    BinaryPrimitives.WriteUInt32LittleEndian(Counters.Slice(0x30), (uint)CommittedSize);
            }

            if (!Instance._emulator.WriteMemory(OutBufferPtr, Counters))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            SetReturnLength(OutBufferLength);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS QueryImageFileName(BinaryEmulator Instance, WinProcess Process, bool Own, bool Win32, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            string FullPath = Own
                ? (Win32 ? Instance.WinHelper.WinModules[0].Path : Instance.GuestImagePath)
                : Process.Path;
            if (string.IsNullOrEmpty(FullPath))
                FullPath = Process.Path ?? string.Empty;

            if (!Win32)
                FullPath = WinSysHelper.ToNtDevicePath(FullPath);

            uint StructSize = (uint)(Instance.WinHelper.PointerSize == 8 ? 0x10 : 0x08);
            int PathByteCount = Encoding.Unicode.GetByteCount(FullPath) + 2;
            if (PathByteCount > ushort.MaxValue)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint RequiredSize = StructSize + (uint)PathByteCount;
            SetReturnLength(RequiredSize);

            if (OutBufferLength < RequiredSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Record = GetSharedWriteBuffer(Instance, RequiredSize);
            ulong BufferPtr = OutBufferPtr + StructSize;

            BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x00, 2), (ushort)(PathByteCount - 2));
            BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x02, 2), (ushort)PathByteCount);
            if (StructSize == 0x10)
                BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(0x08, 8), BufferPtr);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x04, 4), (uint)BufferPtr);

            Encoding.Unicode.GetBytes(FullPath.AsSpan(), Record.Slice((int)StructSize, PathByteCount - 2));

            if (!Instance.WriteMemory(OutBufferPtr, Record))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried the image name of \"{Process.Name}\" = \"{FullPath}\".", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static SECTION_IMAGE_INFORMATION BuildOwnImageInformation(BinaryEmulator Instance, bool Is64Image)
        {
            uint AddressOfEntryPoint = Is64Image
                ? Instance._binary.PE.OptionalHeader64.AddressOfEntryPoint
                : Instance._binary.PE.OptionalHeader32.AddressOfEntryPoint;

            return new SECTION_IMAGE_INFORMATION
            {
                TransferAddress = Instance.WinHelper.WinModules[0].MappedBase + AddressOfEntryPoint,
                MaximumStackSize = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.SizeOfStackReserve
                    : Instance._binary.PE.OptionalHeader32.SizeOfStackReserve,
                CommittedStackSize = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.SizeOfStackCommit
                    : Instance._binary.PE.OptionalHeader32.SizeOfStackCommit,
                SubSystemType = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.Subsystem
                    : Instance._binary.PE.OptionalHeader32.Subsystem,
                SubSystemMinorVersion = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.MinorSubsystemVersion
                    : Instance._binary.PE.OptionalHeader32.MinorSubsystemVersion,
                SubSystemMajorVersion = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.MajorSubsystemVersion
                    : Instance._binary.PE.OptionalHeader32.MajorSubsystemVersion,
                MajorOperatingSystemVersion = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.MajorOperatingSystemVersion
                    : Instance._binary.PE.OptionalHeader32.MajorOperatingSystemVersion,
                MinorOperatingSystemVersion = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.MinorOperatingSystemVersion
                    : Instance._binary.PE.OptionalHeader32.MinorOperatingSystemVersion,
                ImageCharacteristics = Instance._binary.PE.FileHeader.Characteristics,
                DllCharacteristics = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.DllCharacteristics
                    : Instance._binary.PE.OptionalHeader32.DllCharacteristics,
                Machine = Instance._binary.PE.FileHeader.Machine,
                ImageContainsCode = true,
                CheckSum = Is64Image
                    ? Instance._binary.PE.OptionalHeader64.CheckSum
                    : Instance._binary.PE.OptionalHeader32.CheckSum,
            };
        }

        private static uint SessionIdOf(BinaryEmulator Instance, WinProcess Process)
        {
            if (Process.PID == Instance.WinHelper.PID)
                return Process.PrimaryToken?.SessionId ?? 1;

            return Process.PID <= 4 || Process.RunningUser == User.System || Process.RunningUser == User.LocalService ? 0u : 1u;
        }

        private static Span<byte> GetSharedWriteBuffer(BinaryEmulator Instance, uint Size)
        {
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Size);
            Buffer.Clear();
            return Buffer;
        }

        private static void WriteUInt32(Span<byte> Buffer, int Offset, uint Value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        private static void WriteInt64(Span<byte> Buffer, int Offset, long Value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private static NTSTATUS QueryProcessTimes(BinaryEmulator Instance, WinProcess Process, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            const uint StructSize = 0x20;

            SetReturnLength(StructSize);

            if (OutBufferLength < StructSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.WinHelper.UpdateProcessTimes(Process);

            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
            WriteInt64(Buffer, 0x00, Process.CreationTime);
            WriteInt64(Buffer, 0x08, Process.ExitTime);
            WriteInt64(Buffer, 0x10, Process.KernelTime);
            WriteInt64(Buffer, 0x18, Process.UserTime);

            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
