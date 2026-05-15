using System;
using System.Buffers.Binary;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySystemInformation : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                SYSTEM_INFORMATION_CLASS SystemInformationClass = (SYSTEM_INFORMATION_CLASS)Instance.WinHelper.GetArg64(0);
                ulong SystemInformationPtr = Instance.WinHelper.GetArg64(1);
                ulong SystemInformationLength = Instance.WinHelper.GetArg64(2);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(3);

                if (SystemInformationPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (SystemInformationLength == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(SystemInformationPtr, SystemInformationLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                switch (SystemInformationClass)
                {
                    case SYSTEM_INFORMATION_CLASS.SystemProcessorFeaturesBitMapInformation:
                        {
                            if (SystemInformationLength != 0)
                                Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, (uint)SystemInformationLength);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, 0u);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemBuildVersionInformation:
                        {
                            const uint RequiredLength = WindowsVersionInfo.BuildVersionInformationLength;

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            if (SystemInformationLength < RequiredLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            WindowsVersionInfo.WriteBuildVersionInformation(Instance, SystemInformationPtr);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation:
                        {
                            const uint FullSize = 0x30;

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, FullSize);
                            }

                            if (SystemInformationLength < FullSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            long CurrentTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
                            long MaxFileTime = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc).ToFileTimeUtc();
                            DateTime CurrentUtc = DateTime.FromFileTimeUtc(Math.Min(CurrentTime, MaxFileTime));
                            DateTime LocalNow = TimeZoneInfo.ConvertTimeFromUtc(CurrentUtc, TimeZoneInfo.Local);

                            TimeSpan Offset = TimeZoneInfo.Local.GetUtcOffset(CurrentUtc);
                            long TimeZoneBias = -Offset.Ticks;

                            long UPtime100ns = Instance.EmulatedTickCount64 * 10000;
                            long BootTime = CurrentTime - UPtime100ns;

                            uint TimeZoneId = TimeZoneInfo.Local.IsDaylightSavingTime(LocalNow) ? 2u : 1u;

                            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(FullSize);
                            Buffer.Slice(0, (int)FullSize).Clear();

                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x00, 8), BootTime);
                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x08, 8), CurrentTime);
                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x10, 8), TimeZoneBias);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), TimeZoneId);

                            if (!Instance.WriteMemory(SystemInformationPtr, Buffer.Slice(0, (int)FullSize)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            Instance.TriggerEventMessage($"[+] NtQuerySystemInformation: SystemTimeOfDayInformation (Boot=0x{BootTime:X}, Now=0x{CurrentTime:X}, TZId={TimeZoneId}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemTimeZoneInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemCurrentTimeZoneInformation:
                        {
                            uint RequiredLength = 172;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, RequiredLength);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, -120);

                            WriteUnicodeString(Instance, SystemInformationPtr + 4, "@tzres.dll,-342");

                            Instance._emulator.WriteMemory(SystemInformationPtr + 84, 0);

                            WriteUnicodeString(Instance, SystemInformationPtr + 88, "@tzres.dll,-341");

                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 2, (ushort)10);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 4, (ushort)5);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 6, (ushort)23);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 8, (ushort)59);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 10, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 12, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 14, (ushort)0);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 2, (ushort)4);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 4, (ushort)4);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 6, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 8, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 10, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 12, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 14, (ushort)0);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 168, -60);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemNumaProcessorMap:
                        const uint HeaderSize = 0x08;
                        const uint GroupAffinitySize = 0x10;
                        const uint MaxNodes = 0x40;

                        if (SystemInformationLength < sizeof(uint))
                        {
                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)sizeof(uint));
                            }
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        uint ClearSize = (uint)Math.Min(SystemInformationLength, HeaderSize + GroupAffinitySize);
                        Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, ClearSize);

                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, 0u); // HighestNodeNumber = 0

                        uint ReqSize = sizeof(uint);

                        if (SystemInformationLength >= HeaderSize + 8)
                        {
                            ulong ActiveMask = 0xFFFUL; // Single-node active processor mask
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, ActiveMask); // Node0 Mask

                            if (SystemInformationLength >= HeaderSize + 0x0A)
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, (ushort)0);

                            uint MaxEntries = (uint)((SystemInformationLength - HeaderSize) / GroupAffinitySize);
                            if (MaxEntries > MaxNodes)
                                MaxEntries = MaxNodes;

                            ReqSize = HeaderSize + (MaxEntries != 0 ? (MaxEntries * GroupAffinitySize) : 0);
                            if (ReqSize < sizeof(uint)) ReqSize = sizeof(uint);
                        }

                        if (ReturnLengthPtr != 0)
                        {
                            if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            Instance._emulator.WriteMemory(ReturnLengthPtr, ReqSize);
                        }
                        return NTSTATUS.STATUS_SUCCESS;

                    case SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation:
                        {
                            uint RequiredLength = 8;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            uint CodeIntegrityOptions = 0x401;

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 4, CodeIntegrityOptions);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation:
                        {
                            uint RequiredLength = 2;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, (byte)0); // KernelDebuggerEnabled
                            Instance._emulator.WriteMemory(SystemInformationPtr + 1, (byte)1); // KernelDebuggerNotPresent

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemRangeStartInformation:
                        {
                            uint Required = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8u : 4u;

                            if (SystemInformationLength < Required)
                            {
                                if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    Instance._emulator.WriteMemory(ReturnLengthPtr, Required);

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (SystemInformationPtr == 0)
                                return NTSTATUS.STATUS_INVALID_PARAMETER;

                            if (!Instance.IsRegionMapped(SystemInformationPtr, Required))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                            {
                                // Typical x64 kernel range start.
                                ulong RangeStart = 0xFFFF800000000000UL;
                                if (!Instance._emulator.WriteMemory(SystemInformationPtr, RangeStart, 8))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            else
                            {
                                uint RangeStart = 0x80000000u;
                                if (!Instance._emulator.WriteMemory(SystemInformationPtr, RangeStart, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }

                            if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                Instance._emulator.WriteMemory(ReturnLengthPtr, Required);

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemSecureBootInformation:
                        {
                            uint RequiredLength = 2;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, (byte)1); // SecureBootEnabled
                            Instance._emulator.WriteMemory(SystemInformationPtr + 1, (byte)1); // SecureBootCapable

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemControlFlowTransition:
                        Instance.TriggerEventMessage($"[!] Warbird transition query using NtQuerySystemInformation at 0x{Instance.ReadRegister(Instance.IPRegister):X}.", LogFlags.Suspicious);
                        return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                    case SYSTEM_INFORMATION_CLASS.SystemProcessInformation:
                        {
                            List<WinProcess> Processes = Instance.WinHelper.WinProcesses;
                            if (Processes == null)
                                Processes = new List<WinProcess>();

                            ulong EntrySize = 0x70;
                            ulong RequiredLength = (ulong)Processes.Count * EntrySize;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, (uint)RequiredLength);

                            ulong Current = SystemInformationPtr;

                            for (int i = 0; i < Processes.Count; i++)
                            {
                                WinProcess P = Processes[i];

                                uint NextEntryOffset = (i == Processes.Count - 1) ? 0 : (uint)EntrySize;

                                Instance._emulator.WriteMemory(Current + 0x00, NextEntryOffset);
                                Instance._emulator.WriteMemory(Current + 0x04, 1u);

                                ulong ImageNameField = Current + 0x38; // ImageName field which contains the process name.

                                if (!string.IsNullOrEmpty(P.Name) && P.Status != ProtectionStatus.Unaccessible)
                                    Instance.WinHelper.SetUnicodeString(ImageNameField, P.Name);
                                else
                                {
                                    Instance._emulator.WriteMemory(ImageNameField + 0x00, (ushort)0, 2);
                                    Instance._emulator.WriteMemory(ImageNameField + 0x02, (ushort)0, 2);
                                    Instance._emulator.WriteMemory(ImageNameField + 0x08, 0UL);
                                }

                                Instance._emulator.WriteMemory(Current + 0x48, 8);

                                Instance._emulator.WriteMemory(Current + 0x50, (ulong)P.PID); // UniqueProcessId
                                Instance._emulator.WriteMemory(Current + 0x58, (ulong)P.PPID); // InheritedFromUniqueProcessId

                                Current += EntrySize;
                            }

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemProcessorInformation:
                        {
                            const uint RequiredLength = 0x0C;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            ushort ProcessorArchitecture = Instance._binary.Architecture == BinaryArchitecture.x64 ? (ushort)9 : (ushort)0;
                            ushort ProcessorLevel = 6;
                            ushort ProcessorRevision = 0x0100;

                            int CpuCount = Environment.ProcessorCount;
                            if (CpuCount < 1)
                                CpuCount = 1;
                            if (CpuCount > ushort.MaxValue)
                                CpuCount = ushort.MaxValue;

                            ushort MaximumProcessors = (ushort)CpuCount;
                            uint ProcessorFeatureBits = 0;

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, ProcessorArchitecture);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x02, ProcessorLevel);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, ProcessorRevision);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x06, MaximumProcessors);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, ProcessorFeatureBits);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemEmulationBasicInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemBasicInformation:
                        {
                            uint RequiredLength = 0x40;
                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            uint NumberOfPhysicalPages = 0x200000;
                            uint LowestPhysicalPageNumber = 0x00000001;
                            uint HighestPhysicalPageNumber = LowestPhysicalPageNumber + NumberOfPhysicalPages - 1;
                            uint AllocationGranularity = 0x10000;
                            uint TimerResolution = 156250;

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, 0u); // Reserved
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, TimerResolution);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, 4096); // PageSize
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x0C, NumberOfPhysicalPages); // NumberOfPhysicalPages
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, LowestPhysicalPageNumber); // LowestPhysicalPageNumber
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x14, HighestPhysicalPageNumber);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x18, AllocationGranularity);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x20, Instance.BaseAddress);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x28, Instance.MaxAddress);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x30, 0x1);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x38, (byte)Environment.ProcessorCount);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
                            }
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    default:
                        Instance.TriggerEventMessage($"[!] Unsupported NtQuerySystemInformation class: 0x{SystemInformationClass:X}", LogFlags.Issues);
                        break;
                }
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {

            }
            return Instance.WinUnimplemented;
        }
        private static void WriteUnicodeString(BinaryEmulator Instance, ulong Address, string Value)
        {
            int ByteCount = Encoding.Unicode.GetByteCount(Value) + 2;
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((uint)ByteCount);
            Encoding.Unicode.GetBytes(Value.AsSpan(), Buffer);
            Buffer[ByteCount - 2] = 0;
            Buffer[ByteCount - 1] = 0;
            Instance._emulator.WriteMemory(Address, Buffer.Slice(0, ByteCount));
        }

    }
}
