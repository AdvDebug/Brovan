using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySystemInformation : IWinSyscall
    {
        private const uint TimeZoneInformationLength = 172;
        private const uint PerformanceInformationLength = 0x178;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                SYSTEM_INFORMATION_CLASS SystemInformationClass = (SYSTEM_INFORMATION_CLASS)Instance.WinHelper.GetArg(0);
                ulong SystemInformationPtr = Instance.WinHelper.GetArg(1);
                ulong SystemInformationLength = (uint)Instance.WinHelper.GetArg(2);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg(3);

                if (SystemInformationLength != 0 && (SystemInformationPtr == 0 || !Instance.IsRegionMapped(SystemInformationPtr, SystemInformationLength)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                switch (SystemInformationClass)
                {
                    case SYSTEM_INFORMATION_CLASS.SystemProcessorFeaturesBitMapInformation:
                        {
                            if (SystemInformationLength != 0)
                                Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, (uint)SystemInformationLength);

                            return SetReturnLength(Instance, ReturnLengthPtr, 0);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemHypervisorSharedPageInformation:
                        {
                            ulong Page = Instance.WinHelper.KuserSharedData.HypervisorSharedPage;
                            if (Page == 0)
                                return NTSTATUS.STATUS_NOT_SUPPORTED;

                            uint RequiredLength = (uint)Instance.WinHelper.PointerSize;

                            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                                return LengthStatus;

                            if (SystemInformationLength < RequiredLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            Instance.WinHelper.WritePointer(SystemInformationPtr, Page);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemBuildVersionInformation:
                        {
                            const uint RequiredLength = WindowsVersionInfo.BuildVersionInformationLength;

                            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                                return LengthStatus;

                            if (SystemInformationLength < RequiredLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            WindowsVersionInfo.WriteBuildVersionInformation(Instance, SystemInformationPtr);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation:
                        {
                            const uint FullSize = 0x30;

                            // NT fills a shorter buffer with part of the record.
                            if (SystemInformationLength > FullSize)
                            {
                                NTSTATUS LongStatus = SetReturnLength(Instance, ReturnLengthPtr, FullSize);
                                return LongStatus != NTSTATUS.STATUS_SUCCESS ? LongStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            long CurrentTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
                            DateTime CurrentUtc = EmulatedUtcNow(Instance);
                            DateTime LocalNow = TimeZoneInfo.ConvertTimeFromUtc(CurrentUtc, TimeZoneInfo.Local);

                            TimeSpan Offset = TimeZoneInfo.Local.GetUtcOffset(CurrentUtc);
                            long TimeZoneBias = -Offset.Ticks;

                            long UPtime100ns = Instance.EmulatedTickCount64 * 10000;
                            long BootTime = CurrentTime - UPtime100ns;

                            uint TimeZoneId = TimeZoneInfo.Local.IsDaylightSavingTime(LocalNow) ? 2u : 1u;

                            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(FullSize);
                            Buffer.Clear();

                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x00, 8), BootTime);
                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x08, 8), CurrentTime);
                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x10, 8), TimeZoneBias);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), TimeZoneId);

                            if (SystemInformationLength != 0 && !Instance.WriteMemory(SystemInformationPtr, Buffer.Slice(0, (int)SystemInformationLength)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQuerySystemInformation: SystemTimeOfDayInformation (Boot=0x{BootTime:X}, Now=0x{CurrentTime:X}, TZId={TimeZoneId}).", LogFlags.Syscall);
                            return SetReturnLength(Instance, ReturnLengthPtr, (uint)SystemInformationLength);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemTimeZoneInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemCurrentTimeZoneInformation:
                        {
                            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, TimeZoneInformationLength);
                            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                                return LengthStatus;

                            if (SystemInformationLength < TimeZoneInformationLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            Span<byte> Zone = Instance.WinHelper.Shared.GetSpan(TimeZoneInformationLength);
                            WriteTimeZoneInformation(Instance, Zone);
                            return Instance.WriteMemory(SystemInformationPtr, Zone) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemRecommendedSharedDataAlignment:
                        {
                            const uint CacheLineAlignment = 64;
                            const uint RequiredLength = sizeof(uint);

                            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                                return LengthStatus;

                            if (SystemInformationLength < RequiredLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance._emulator.WriteMemory(SystemInformationPtr, CacheLineAlignment))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemNumaProcessorMap:
                        {
                            // SYSTEM_NUMA_INFORMATION: HighestNodeNumber, then one GROUP_AFFINITY per node at 8.
                            if (SystemInformationLength < sizeof(uint))
                            {
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, sizeof(uint));
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (!Instance._emulator.WriteMemory(SystemInformationPtr, 0u))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint GroupAffinitySize = Instance.WinHelper.PointerSize == 8 ? 0x10u : 0x0Cu;
                            if (SystemInformationLength < 0x08 + GroupAffinitySize)
                                return SetReturnLength(Instance, ReturnLengthPtr, sizeof(uint));

                            Span<byte> Affinity = stackalloc byte[0x10];
                            Affinity.Clear();
                            if (Instance.WinHelper.PointerSize == 8)
                                BinaryPrimitives.WriteUInt64LittleEndian(Affinity, Instance.WinHelper.ActiveProcessorMask);
                            else
                                BinaryPrimitives.WriteUInt32LittleEndian(Affinity, (uint)Instance.WinHelper.ActiveProcessorMask);

                            if (!Instance.WriteMemory(SystemInformationPtr + 0x08, Affinity.Slice(0, (int)GroupAffinitySize)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            return SetReturnLength(Instance, ReturnLengthPtr, 0x08 + GroupAffinitySize);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation:
                        {
                            uint RequiredLength = 8;

                            if (SystemInformationLength < RequiredLength)
                            {
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            uint CodeIntegrityOptions = 0x401;

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 4, CodeIntegrityOptions);

                            return SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation:
                        {
                            uint RequiredLength = 2;

                            if (SystemInformationLength < RequiredLength)
                            {
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            // KernelDebuggerEnabled, KernelDebuggerNotPresent.
                            if (!Instance.WinHelper.WriteByte(SystemInformationPtr + 0, 0) || !Instance.WinHelper.WriteByte(SystemInformationPtr + 1, 1))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            return SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
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
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            // SecureBootEnabled, SecureBootCapable.
                            if (!Instance.WinHelper.WriteByte(SystemInformationPtr + 0, 1) || !Instance.WinHelper.WriteByte(SystemInformationPtr + 1, 1))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            return SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemControlFlowTransition:
                        if ((Instance.Settings.Flags & LogFlags.Suspicious) != 0)
                            Instance.TriggerEventMessage($"[!] Warbird transition query using NtQuerySystemInformation at 0x{Instance.ReadRegister(Instance.IPRegister):X}.", LogFlags.Suspicious);
                        return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                    case SYSTEM_INFORMATION_CLASS.SystemProcessInformation:
                        {
                            bool Written = Instance.WinHelper.TryWriteProcessInformationList(SystemInformationPtr, (uint)SystemInformationLength, out uint RequiredLength);

                            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                                return LengthStatus;

                            return Written ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemProcessorInformation:
                        {
                            const uint RequiredLength = 0x0C;

                            if (SystemInformationLength < RequiredLength)
                            {
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            ushort ProcessorArchitecture = Instance._binary.Architecture == BinaryArchitecture.x64 ? (ushort)9 : (ushort)0;
                            ushort ProcessorLevel = 6;
                            ushort ProcessorRevision = 0x0100;
                            ushort MaximumProcessors = (ushort)Instance.WinHelper.ProcessorCount;
                            uint ProcessorFeatureBits = 0;

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, ProcessorArchitecture);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x02, ProcessorLevel);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, ProcessorRevision);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x06, MaximumProcessors);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, ProcessorFeatureBits);

                            return SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemProcessorPerformanceInformation:
                        return QueryProcessorPerformance(Instance, SystemInformationPtr, (uint)SystemInformationLength, ReturnLengthPtr);

                    case SYSTEM_INFORMATION_CLASS.SystemPerformanceInformation:
                        {
                            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, PerformanceInformationLength);
                            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                                return LengthStatus;

                            if (SystemInformationLength < PerformanceInformationLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            Span<byte> Performance = Instance.WinHelper.Shared.GetSpan(PerformanceInformationLength);
                            WritePerformanceInformation(Instance, Performance);
                            return Instance.WriteMemory(SystemInformationPtr, Performance) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemHandleInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation:
                        return QueryHandles(Instance, SystemInformationClass == SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation, SystemInformationPtr, (uint)SystemInformationLength, ReturnLengthPtr);

                    case SYSTEM_INFORMATION_CLASS.SystemLogicalProcessorInformation:
                        // WOW64 does not thunk this class.
                        if (Instance.WinHelper.PointerSize != 8)
                            return NTSTATUS.STATUS_INVALID_INFO_CLASS;

                        return NtQuerySystemInformationEx.QueryLegacyProcessorInformation(Instance, SystemInformationPtr, (uint)SystemInformationLength, ReturnLengthPtr);

                    // GlobalMemoryStatusEx reads its figures here, not from SystemBasicInformation. The class
                    // number moved between builds, and 10.0.26100 asks for 0xC0 under a name this table gives
                    // to something else. The record did not move and is the same on x86 and x64.
                    case SYSTEM_INFORMATION_CLASS.SystemMemoryUsageInformation:
                    case (SYSTEM_INFORMATION_CLASS)0xC0:
                        {
                            const uint RequiredLength = 0x38;

                            if (SystemInformationLength < RequiredLength)
                            {
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            GetMemoryFigures(out ulong TotalBytes, out ulong AvailableBytes, out ulong CommittedBytes, out ulong CommitLimitBytes);

                            Span<byte> Usage = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                            Usage.Clear();
                            BinaryPrimitives.WriteUInt64LittleEndian(Usage.Slice(0x00), TotalBytes);
                            BinaryPrimitives.WriteUInt64LittleEndian(Usage.Slice(0x08), AvailableBytes);
                            BinaryPrimitives.WriteUInt64LittleEndian(Usage.Slice(0x18), CommittedBytes);
                            BinaryPrimitives.WriteUInt64LittleEndian(Usage.Slice(0x28), CommitLimitBytes);

                            if (!Instance._emulator.WriteMemory(SystemInformationPtr, Usage))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            return SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemEmulationBasicInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemBasicInformation:
                        {
                            // The ULONG_PTR fields and NumberOfProcessors follow the pointer width.
                            const ulong MinimumUserModeAddress = 0x10000UL;
                            ulong PointerSize = (ulong)Instance.WinHelper.PointerSize;
                            ulong PointerFields = SystemInformationPtr + (PointerSize == 8 ? 0x20u : 0x1Cu);
                            uint RequiredLength = PointerSize == 8 ? 0x40u : 0x2Cu;
                            if (SystemInformationLength < RequiredLength)
                            {
                                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            uint NumberOfPhysicalPages = Settings.MemoryBudget.GuestPhysicalPages;
                            uint LowestPhysicalPageNumber = 0x00000001;
                            uint HighestPhysicalPageNumber = LowestPhysicalPageNumber + NumberOfPhysicalPages - 1;
                            uint AllocationGranularity = 0x10000;
                            uint TimerResolution = 156250;

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, TimerResolution);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, 4096u); // PageSize
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x0C, NumberOfPhysicalPages);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, LowestPhysicalPageNumber);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x14, HighestPhysicalPageNumber);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x18, AllocationGranularity);

                            Instance.WinHelper.WritePointer(PointerFields, MinimumUserModeAddress);
                            Instance.WinHelper.WritePointer(PointerFields + PointerSize, Instance.MaxAddress);
                            Instance.WinHelper.WritePointer(PointerFields + PointerSize * 2, Instance.WinHelper.ActiveProcessorMask);
                            Instance.WinHelper.WriteByte(PointerFields + PointerSize * 3, (byte)Instance.WinHelper.ProcessorCount);

                            return SetReturnLength(Instance, ReturnLengthPtr, RequiredLength);
                        }
                    default:
                        if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                            Instance.TriggerEventMessage($"[!] Unsupported NtQuerySystemInformation class: 0x{SystemInformationClass:X}", LogFlags.Issues);
                        break;
                }
            }
            return Instance.WinUnimplemented;
        }

        private static NTSTATUS SetReturnLength(BinaryEmulator Instance, ulong ReturnLengthPtr, uint Length)
        {
            if (ReturnLengthPtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(ReturnLengthPtr, Length);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS QueryProcessorPerformance(BinaryEmulator Instance, ulong Buffer, uint Length, ulong ReturnLengthPtr)
        {
            const uint EntrySize = 0x30;

            uint CpuCount = Instance.WinHelper.ProcessorCount;
            if (Length < EntrySize)
            {
                NTSTATUS ShortStatus = SetReturnLength(Instance, ReturnLengthPtr, EntrySize * CpuCount);
                return ShortStatus != NTSTATUS.STATUS_SUCCESS ? ShortStatus : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            uint Entries = Math.Min(CpuCount, Length / EntrySize);
            uint WrittenSize = Entries * EntrySize;

            Instance.WinHelper.GetProcessorTimes(out long IdleTime, out long KernelTime, out long UserTime);

            Span<byte> Times = Instance.WinHelper.Shared.GetSpan(WrittenSize);
            Times.Clear();
            for (int i = 0; i < Entries; i++)
            {
                Span<byte> Entry = Times.Slice(i * (int)EntrySize, (int)EntrySize);
                BinaryPrimitives.WriteInt64LittleEndian(Entry.Slice(0x00, 8), IdleTime);
                BinaryPrimitives.WriteInt64LittleEndian(Entry.Slice(0x08, 8), KernelTime);
                BinaryPrimitives.WriteInt64LittleEndian(Entry.Slice(0x10, 8), UserTime);
            }

            if (!Instance.WriteMemory(Buffer, Times))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return SetReturnLength(Instance, ReturnLengthPtr, WrittenSize);
        }

        private static void GetMemoryFigures(out ulong TotalBytes, out ulong AvailableBytes, out ulong CommittedBytes, out ulong CommitLimitBytes)
        {
            TotalBytes = Settings.MemoryBudget.GuestPhysicalBytes;
            AvailableBytes = TotalBytes / 4 * 3;
            CommitLimitBytes = TotalBytes * 2;
            CommittedBytes = TotalBytes - AvailableBytes;
        }

        // SYSTEM_PERFORMANCE_INFORMATION is the same size on both architectures.
        private static void WritePerformanceInformation(BinaryEmulator Instance, Span<byte> Record)
        {
            Record.Clear();
            GetMemoryFigures(out _, out ulong AvailableBytes, out ulong CommittedBytes, out ulong CommitLimitBytes);
            Instance.WinHelper.GetProcessorTimes(out long IdleTime, out _, out _);

            BinaryPrimitives.WriteInt64LittleEndian(Record.Slice(0x00, 8), IdleTime * Instance.WinHelper.ProcessorCount);
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x2C, 4), (uint)(AvailableBytes / 4096));
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x30, 4), (uint)(CommittedBytes / 4096));
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x34, 4), (uint)(CommitLimitBytes / 4096));
            BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x38, 4), (uint)(CommittedBytes / 4096));
        }

        private static DateTime EmulatedUtcNow(BinaryEmulator Instance)
        {
            long MaxFileTime = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc).ToFileTimeUtc();
            return DateTime.FromFileTimeUtc(Math.Clamp(Instance.GetEmulatedSystemTimeFileTimeUtc(), 0, MaxFileTime));
        }

        // A floating TIME_FIELDS rule keeps the week in Day and the day of the week in Weekday.
        private static void WriteTimeZoneInformation(BinaryEmulator Instance, Span<byte> Zone)
        {
            Zone.Clear();

            TimeZoneInfo Local = TimeZoneInfo.Local;
            DateTime Today = EmulatedUtcNow(Instance).Date;
            TimeZoneInfo.AdjustmentRule? Rule = null;
            foreach (TimeZoneInfo.AdjustmentRule Candidate in Local.GetAdjustmentRules())
            {
                if (Candidate.DateStart <= Today && Candidate.DateEnd >= Today)
                    Rule = Candidate;
            }

            TimeSpan StandardOffset = Local.BaseUtcOffset + (Rule?.BaseUtcOffsetDelta ?? TimeSpan.Zero);
            BinaryPrimitives.WriteInt32LittleEndian(Zone.Slice(0, 4), -(int)StandardOffset.TotalMinutes);
            WriteZoneName(Zone.Slice(4, 64), Local.StandardName);
            WriteZoneName(Zone.Slice(88, 64), Local.DaylightName);

            if (Rule == null || Rule.DaylightDelta == TimeSpan.Zero)
                return;

            WriteTransition(Zone.Slice(68, 16), Rule.DaylightTransitionEnd);
            WriteTransition(Zone.Slice(152, 16), Rule.DaylightTransitionStart);
            BinaryPrimitives.WriteInt32LittleEndian(Zone.Slice(168, 4), -(int)Rule.DaylightDelta.TotalMinutes);
        }

        private static void WriteZoneName(Span<byte> Target, string Name)
        {
            if (string.IsNullOrEmpty(Name))
                return;

            Encoding.Unicode.GetBytes(Name.AsSpan(0, Math.Min(Name.Length, 31)), Target);
        }

        private static void WriteTransition(Span<byte> Fields, TimeZoneInfo.TransitionTime Transition)
        {
            DateTime Time = Transition.TimeOfDay;
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x02, 2), (short)Transition.Month);
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x04, 2), (short)(Transition.IsFixedDateRule ? Transition.Day : Transition.Week));
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x06, 2), (short)Time.Hour);
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x08, 2), (short)Time.Minute);
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x0A, 2), (short)Time.Second);
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x0C, 2), (short)Time.Millisecond);
            BinaryPrimitives.WriteInt16LittleEndian(Fields.Slice(0x0E, 2), (short)(Transition.IsFixedDateRule ? 0 : (int)Transition.DayOfWeek));
        }

        // NT hides the object address from a caller without SeDebugPrivilege.
        private static NTSTATUS QueryHandles(BinaryEmulator Instance, bool Extended, ulong Buffer, uint Length, ulong ReturnLengthPtr)
        {
            bool Wide = Instance.WinHelper.PointerSize == 8;
            uint HeaderSize = Extended ? (Wide ? 0x10u : 0x08u) : (Wide ? 0x08u : 0x04u);
            uint EntrySize = Extended ? (Wide ? 0x28u : 0x1Cu) : (Wide ? 0x18u : 0x10u);

            List<KeyValuePair<ulong, IHandleObject>> Handles = Instance.WinHelper.HandleManager.SnapshotHandles();
            ulong Required = HeaderSize + (ulong)Handles.Count * EntrySize;
            if (Required > uint.MaxValue)
                return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

            NTSTATUS LengthStatus = SetReturnLength(Instance, ReturnLengthPtr, (uint)Required);
            if (LengthStatus != NTSTATUS.STATUS_SUCCESS)
                return LengthStatus;

            if (Length < Required)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            Span<byte> Header = stackalloc byte[0x10];
            Header.Clear();
            if (Wide && Extended)
                BinaryPrimitives.WriteUInt64LittleEndian(Header, (ulong)Handles.Count);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Header, (uint)Handles.Count);

            if (!Instance._emulator.WriteMemory(Buffer, Header.Slice(0, (int)HeaderSize)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Pid = Instance.WinHelper.PID;
            Span<byte> Entry = stackalloc byte[0x28];
            ulong Cursor = Buffer + HeaderSize;
            foreach (KeyValuePair<ulong, IHandleObject> Handle in Handles)
            {
                Entry.Clear();
                uint Granted = (uint)Instance.WinHelper.HandleManager.GetPermissionsByHandle(Handle.Key);
                ObjectHandleFlags Flags = Instance.WinHelper.HandleManager.GetHandleFlags(Handle.Key);

                // OBJ_PROTECT_CLOSE is 1, OBJ_INHERIT is 2. NT numbers object types from 2.
                byte Attributes = (byte)(((Flags & ObjectHandleFlags.ProtectFromClose) != 0 ? 1 : 0) | ((Flags & ObjectHandleFlags.Inherit) != 0 ? 2 : 0));
                ushort TypeIndex = (ushort)((int)Handle.Value.ObjectType + 2);

                if (Extended)
                {
                    int Field = Wide ? 8 : 4;
                    WriteField(Entry.Slice(Field), Pid, Wide);
                    WriteField(Entry.Slice(Field * 2), Handle.Key, Wide);
                    BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(Field * 3), Granted);
                    BinaryPrimitives.WriteUInt16LittleEndian(Entry.Slice(Field * 3 + 6), TypeIndex);
                    BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(Field * 3 + 8), Attributes);
                }
                else
                {
                    BinaryPrimitives.WriteUInt16LittleEndian(Entry, (ushort)Pid);
                    Entry[4] = (byte)TypeIndex;
                    Entry[5] = Attributes;
                    BinaryPrimitives.WriteUInt16LittleEndian(Entry.Slice(6), (ushort)Handle.Key);
                    BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(Wide ? 0x10 : 0x0C), Granted);
                }

                if (!Instance._emulator.WriteMemory(Cursor, Entry.Slice(0, (int)EntrySize)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Cursor += EntrySize;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteField(Span<byte> Target, ulong Value, bool Wide)
        {
            if (Wide)
                BinaryPrimitives.WriteUInt64LittleEndian(Target, Value);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Target, (uint)Value);
        }
    }
}
