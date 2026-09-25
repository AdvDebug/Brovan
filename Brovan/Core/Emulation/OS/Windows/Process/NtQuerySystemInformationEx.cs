using System;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySystemInformationEx : IWinSyscall
    {
        private const uint RelationProcessorCore = 0;
        private const uint RelationNumaNode = 1;
        private const uint RelationCache = 2;
        private const uint RelationProcessorPackage = 3;
        private const uint RelationGroup = 4;
        private const uint RelationProcessorDie = 5;
        private const uint RelationNumaNodeEx = 6;
        private const uint RelationProcessorModule = 7;
        private const uint RelationAll = 0xFFFF;

        private const uint CacheUnified = 0;
        private const uint CacheInstruction = 1;
        private const uint CacheData = 2;

        private const ushort CacheLineSize = 64;
        private const uint L1CacheSize = 0x8000;
        private const uint L2CacheSize = 0x80000;
        private const uint L3CacheSize = 0x800000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            SYSTEM_INFORMATION_CLASS SystemInformationClass = (SYSTEM_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg(0);
            ulong InputBufferPtr = Instance.WinHelper.GetArg(1);
            ulong InputBufferLength = (uint)Instance.WinHelper.GetArg(2);
            ulong SystemInformationPtr = Instance.WinHelper.GetArg(3);
            ulong SystemInformationLength = (uint)Instance.WinHelper.GetArg(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(5);

            if (InputBufferLength != 0)
            {
                if (InputBufferPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(InputBufferPtr, InputBufferLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (SystemInformationLength != 0)
            {
                if (SystemInformationPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(SystemInformationPtr, SystemInformationLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            else
            {
                if (SystemInformationPtr != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            NTSTATUS WriteReturnLength(uint Value)
            {
                if (ReturnLengthPtr == 0)
                    return NTSTATUS.STATUS_SUCCESS;

                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(ReturnLengthPtr, Value);
                return NTSTATUS.STATUS_SUCCESS;
            }

            switch (SystemInformationClass)
            {
                case SYSTEM_INFORMATION_CLASS.SystemFeatureConfigurationInformation:
                    {
                        const uint InputRequired = 0x08;
                        const uint OutputRequired = 0x18;

                        if (InputBufferPtr == 0 || InputBufferLength < InputRequired)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (SystemInformationPtr == 0)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        NTSTATUS rl = WriteReturnLength(OutputRequired);
                        if (rl != NTSTATUS.STATUS_SUCCESS)
                            return rl;

                        if (SystemInformationLength < OutputRequired)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        uint ConfigurationType = Instance.ReadMemoryUInt(InputBufferPtr + 0x00);
                        uint FeatureId = Instance.ReadMemoryUInt(InputBufferPtr + 0x04);

                        Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, OutputRequired);

                        ulong ChangeStamp = 1;
                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, ChangeStamp);

                        // Configuration.FeatureId
                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, FeatureId);

                        // Configuration.Flags: leave 0 => Priority=0, EnabledState=Default (0), etc.
                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x0C, 0u);

                        // Configuration.VariantPayload
                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, 0u);

                        if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                            Instance.TriggerEventMessage($"[+] NtQuerySystemInformationEx: SystemFeatureConfigurationInformation (Type={ConfigurationType}, FeatureId={FeatureId}, Stamp={ChangeStamp}).", LogFlags.Syscall);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case SYSTEM_INFORMATION_CLASS.SystemFeatureConfigurationSectionInformation:
                    {
                        const uint SectionTypeCount = 3;
                        const uint InputRequired = 8 * SectionTypeCount; // 0x18
                        const uint OutputRequired = 0x50; // 8 + (3 * 0x18)

                        if (InputBufferPtr == 0 || InputBufferLength < InputRequired)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (SystemInformationPtr == 0)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        NTSTATUS rl = WriteReturnLength(OutputRequired);
                        if (rl != NTSTATUS.STATUS_SUCCESS)
                            return rl;

                        if (SystemInformationLength < OutputRequired)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, OutputRequired);

                        ulong OverallChangeStamp = 1;
                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, OverallChangeStamp);

                        // Preserve nonzero previous change stamps for callers tracking section updates.
                        for (uint i = 0; i < SectionTypeCount; i++)
                        {
                            ulong Prev = Instance.ReadMemoryULong(InputBufferPtr + (i * 8));
                            ulong EntryBase = SystemInformationPtr + 0x08 + (i * 0x18);

                            // ChangeStamp
                            Instance._emulator.WriteMemory(EntryBase + 0x00, Prev == 0 ? OverallChangeStamp : Prev);
                            // Section pointer = 0
                            Instance._emulator.WriteMemory(EntryBase + 0x08, 0UL);
                            // Size = 0
                            Instance._emulator.WriteMemory(EntryBase + 0x10, 0UL);
                        }

                        if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                            Instance.TriggerEventMessage($"[+] NtQuerySystemInformationEx: SystemFeatureConfigurationSectionInformation (Stamp={OverallChangeStamp}).", LogFlags.Syscall);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case SYSTEM_INFORMATION_CLASS.SystemBuildVersionInformation:
                    {
                        const uint RequiredLength = WindowsVersionInfo.BuildVersionInformationLength;

                        if (InputBufferLength != 0 && InputBufferLength < sizeof(uint))
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        NTSTATUS rl = WriteReturnLength(RequiredLength);
                        if (rl != NTSTATUS.STATUS_SUCCESS)
                            return rl;

                        if (SystemInformationLength < RequiredLength)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        WindowsVersionInfo.WriteBuildVersionInformation(Instance, SystemInformationPtr);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case SYSTEM_INFORMATION_CLASS.SystemProcessorPerformanceInformation:
                    {
                        NTSTATUS GroupStatus = CheckProcessorGroup(Instance, InputBufferPtr, InputBufferLength);
                        if (GroupStatus != NTSTATUS.STATUS_SUCCESS)
                            return GroupStatus;

                        return NtQuerySystemInformation.QueryProcessorPerformance(Instance, SystemInformationPtr, (uint)SystemInformationLength, ReturnLengthPtr);
                    }

                case SYSTEM_INFORMATION_CLASS.SystemLogicalProcessorInformation:
                    {
                        NTSTATUS GroupStatus = CheckProcessorGroup(Instance, InputBufferPtr, InputBufferLength);
                        if (GroupStatus != NTSTATUS.STATUS_SUCCESS)
                            return GroupStatus;

                        return QueryLegacyProcessorInformation(Instance, SystemInformationPtr, (uint)SystemInformationLength, ReturnLengthPtr);
                    }

                case SYSTEM_INFORMATION_CLASS.SystemLogicalProcessorAndGroupInformation:
                    {
                        if (InputBufferPtr == 0 || InputBufferLength < sizeof(uint))
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        uint Relationship = Instance.ReadMemoryUInt(InputBufferPtr);
                        int RequiredLength = WriteProcessorRelations(Instance, Relationship, Span<byte>.Empty);
                        if (RequiredLength < 0)
                        {
                            if ((Instance.Settings.Flags & LogFlags.Suspicious) != 0)
                                Instance.TriggerEventMessage($"[!] Unsupported SystemLogicalProcessorAndGroupInformation request: 0x{Relationship:X}.", LogFlags.Suspicious);
                            return NTSTATUS.STATUS_UNSUCCESSFUL;
                        }

                        NTSTATUS RL = WriteReturnLength((uint)RequiredLength);
                        if (RL != NTSTATUS.STATUS_SUCCESS)
                            return RL;

                        if (SystemInformationLength < (uint)RequiredLength)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        Span<byte> Relations = Instance.WinHelper.Shared.GetSpan((uint)RequiredLength);
                        WriteProcessorRelations(Instance, Relationship, Relations);
                        return Instance.WriteMemory(SystemInformationPtr, Relations) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                case SYSTEM_INFORMATION_CLASS.SystemControlFlowTransition:
                    if ((Instance.Settings.Flags & LogFlags.Suspicious) != 0)
                        Instance.TriggerEventMessage($"[!] Warbird transition query using NtQuerySystemInformationEx at 0x{Instance.ReadRegister(Instance.IPRegister):X}.", LogFlags.Suspicious);
                    return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                case SYSTEM_INFORMATION_CLASS.SystemSupportedProcessorArchitectures:
                case SYSTEM_INFORMATION_CLASS.SystemSupportedProcessorArchitectures2:
                    {
                        const uint RequiredLength = 12;

                        if (InputBufferPtr == 0 || InputBufferLength != (ulong)Instance.WinHelper.PointerSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        BinaryArchitecture Architecture = BinaryArchitecture.Unknown;
                        ulong ProcessHandle = Instance.WinHelper.ReadPointer(InputBufferPtr);
                        if (ProcessHandle != 0)
                        {
                            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation, out WinProcess Process);
                            if (Status != NTSTATUS.STATUS_SUCCESS)
                                return Status;

                            Architecture = Process.PID == Instance.WinHelper.PID ? Instance._binary.Architecture : Process.Arch;
                        }

                        NTSTATUS RL = WriteReturnLength(RequiredLength);
                        if (RL != NTSTATUS.STATUS_SUCCESS)
                            return RL;

                        if (SystemInformationLength < RequiredLength)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        // AMD64 native in both modes, I386 user mode under WOW64, then a zero entry. Bit 19 marks the
                        // queried process's architecture.
                        Span<byte> Machines = stackalloc byte[(int)RequiredLength];
                        Machines.Clear();
                        BinaryPrimitives.WriteUInt32LittleEndian(Machines, 0x78664u | (Architecture == BinaryArchitecture.x64 ? 0x80000u : 0u));
                        BinaryPrimitives.WriteUInt32LittleEndian(Machines.Slice(4), 0x12014Cu | (Architecture == BinaryArchitecture.x86 ? 0x80000u : 0u));
                        return Instance.WriteMemory(SystemInformationPtr, Machines) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                // NtQuerySystemInformation only. WOW64 refuses them before it reads the input.
                case SYSTEM_INFORMATION_CLASS.SystemBasicInformation:
                case SYSTEM_INFORMATION_CLASS.SystemEmulationBasicInformation:
                case SYSTEM_INFORMATION_CLASS.SystemProcessorInformation:
                case SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation:
                case SYSTEM_INFORMATION_CLASS.SystemProcessInformation:
                case SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation:
                case SYSTEM_INFORMATION_CLASS.SystemCurrentTimeZoneInformation:
                case SYSTEM_INFORMATION_CLASS.SystemTimeZoneInformation:
                case SYSTEM_INFORMATION_CLASS.SystemRangeStartInformation:
                case SYSTEM_INFORMATION_CLASS.SystemNumaProcessorMap:
                case SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation:
                case SYSTEM_INFORMATION_CLASS.SystemSecureBootInformation:
                    return Instance.WinHelper.PointerSize == 8 && InputBufferLength == 0 ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_INVALID_INFO_CLASS;

                default:
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[-] Unsupported SYSTEM_INFO_CLASS: 0x{SystemInformationClass:X}", LogFlags.Issues);
                    return Instance.WinUnimplemented;
            }
        }

        private static NTSTATUS CheckProcessorGroup(BinaryEmulator Instance, ulong InputBufferPtr, ulong InputBufferLength)
        {
            if (InputBufferPtr == 0 || InputBufferLength < sizeof(ushort))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return Instance._emulator.ReadMemoryUShort(InputBufferPtr) == 0 ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        internal static NTSTATUS QueryLegacyProcessorInformation(BinaryEmulator Instance, ulong Buffer, uint Length, ulong ReturnLengthPtr)
        {
            int RequiredLength = WriteLegacyProcessorInformation(Instance, Span<byte>.Empty);

            if (ReturnLengthPtr != 0)
            {
                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
            }

            if (Length < (uint)RequiredLength)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            Span<byte> Processors = Instance.WinHelper.Shared.GetSpan((uint)RequiredLength);
            WriteLegacyProcessorInformation(Instance, Processors);
            return Instance.WriteMemory(Buffer, Processors) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static int WriteLegacyProcessorInformation(BinaryEmulator Instance, Span<byte> Target)
        {
            bool Wide = Instance.WinHelper.PointerSize == 8;
            int EntrySize = Wide ? 0x20 : 0x18;
            uint Count = Instance.WinHelper.ProcessorCount;
            ulong All = Instance.WinHelper.ActiveProcessorMask;
            int Required = (int)(Count * 4 + 3) * EntrySize;

            if (Target.Length < Required)
                return Required;

            Target = Target.Slice(0, Required);
            Target.Clear();

            int Offset = 0;
            for (int Index = 0; Index < Count; Index++)
            {
                ulong Mask = 1UL << Index;
                NextLegacyEntry(Target, ref Offset, Wide, RelationProcessorCore, Mask);
                WriteCacheDescriptor(NextLegacyEntry(Target, ref Offset, Wide, RelationCache, Mask), 1, 8, L1CacheSize, CacheData);
                WriteCacheDescriptor(NextLegacyEntry(Target, ref Offset, Wide, RelationCache, Mask), 1, 8, L1CacheSize, CacheInstruction);
                WriteCacheDescriptor(NextLegacyEntry(Target, ref Offset, Wide, RelationCache, Mask), 2, 8, L2CacheSize, CacheUnified);
            }

            NextLegacyEntry(Target, ref Offset, Wide, RelationProcessorPackage, All);
            WriteCacheDescriptor(NextLegacyEntry(Target, ref Offset, Wide, RelationCache, All), 3, 16, L3CacheSize, CacheUnified);
            NextLegacyEntry(Target, ref Offset, Wide, RelationNumaNode, All);
            return Required;
        }

        private static Span<byte> NextLegacyEntry(Span<byte> Target, ref int Offset, bool Wide, uint Relationship, ulong Mask)
        {
            Span<byte> Entry = Target.Slice(Offset, Wide ? 0x20 : 0x18);
            Offset += Entry.Length;
            WriteMask(Entry, Mask, Wide);
            BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(Wide ? 8 : 4), Relationship);
            return Entry.Slice(Wide ? 0x10 : 0x08);
        }

        internal static int WriteProcessorRelations(BinaryEmulator Instance, uint Relationship, Span<byte> Target)
        {
            if (Relationship > RelationProcessorModule && Relationship != RelationAll)
                return -1;

            bool Wide = Instance.WinHelper.PointerSize == 8;
            uint Count = Instance.WinHelper.ProcessorCount;
            ulong All = Instance.WinHelper.ActiveProcessorMask;

            RelationWriter Measure = new RelationWriter(Relationship, Wide, Span<byte>.Empty);
            WriteRelations(ref Measure, Count, All);
            if (Target.Length < Measure.Length)
                return Measure.Length;

            RelationWriter Writer = new RelationWriter(Relationship, Wide, Target.Slice(0, Measure.Length));
            WriteRelations(ref Writer, Count, All);
            return Writer.Length;
        }

        // NT's entry order.
        private static void WriteRelations(ref RelationWriter Writer, uint Count, ulong All)
        {
            Writer.Processor(RelationProcessorPackage, All);
            for (int Index = 0; Index < Count; Index++)
            {
                ulong Mask = 1UL << Index;
                Writer.Processor(RelationProcessorCore, Mask);
                Writer.Processor(RelationProcessorModule, Mask);
                Writer.Cache(1, 8, L1CacheSize, CacheData, Mask);
                Writer.Cache(1, 8, L1CacheSize, CacheInstruction, Mask);
                Writer.Cache(2, 8, L2CacheSize, CacheUnified, Mask);
                if (Index == 0)
                    Writer.Cache(3, 16, L3CacheSize, CacheUnified, All);
            }
            Writer.Numa(All);
            Writer.Group(Count, All);
            Writer.Processor(RelationProcessorDie, All);
        }

        private ref struct RelationWriter
        {
            private readonly uint Wanted;
            private readonly bool Wide;
            private readonly Span<byte> Target;
            public int Length;

            public RelationWriter(uint Wanted, bool Wide, Span<byte> Target)
            {
                this.Wanted = Wanted;
                this.Wide = Wide;
                this.Target = Target;
                Length = 0;
                Target.Clear();
            }

            private int GroupAffinitySize => Wide ? 0x10 : 0x0C;

            // RelationAll leaves the die out. RelationNumaNodeEx reports RelationNumaNode entries.
            private bool Includes(uint Relationship)
            {
                if (Wanted == RelationAll)
                    return Relationship != RelationProcessorDie;

                return Wanted == Relationship || (Wanted == RelationNumaNodeEx && Relationship == RelationNumaNode);
            }

            private Span<byte> Next(uint Relationship, int Size)
            {
                int Offset = Length;
                Length += Size;
                if (Target.IsEmpty)
                    return Span<byte>.Empty;

                Span<byte> Entry = Target.Slice(Offset, Size);
                BinaryPrimitives.WriteUInt32LittleEndian(Entry, Relationship);
                BinaryPrimitives.WriteUInt32LittleEndian(Entry.Slice(4), (uint)Size);
                return Entry;
            }

            // NUMA_NODE_RELATIONSHIP shares this layout: GroupCount at 0x1E, then the GROUP_AFFINITY.
            public void Processor(uint Relationship, ulong Mask)
            {
                if (!Includes(Relationship))
                    return;

                Span<byte> Entry = Next(Relationship, 0x20 + GroupAffinitySize);
                if (Entry.IsEmpty)
                    return;

                BinaryPrimitives.WriteUInt16LittleEndian(Entry.Slice(0x1E), 1);
                WriteMask(Entry.Slice(0x20), Mask, Wide);
            }

            public void Numa(ulong Mask) => Processor(RelationNumaNode, Mask);

            public void Cache(byte Level, byte Associativity, uint Size, uint Type, ulong Mask)
            {
                if (!Includes(RelationCache))
                    return;

                Span<byte> Entry = Next(RelationCache, 0x28 + GroupAffinitySize);
                if (Entry.IsEmpty)
                    return;

                WriteCacheDescriptor(Entry.Slice(0x08), Level, Associativity, Size, Type);
                BinaryPrimitives.WriteUInt16LittleEndian(Entry.Slice(0x26), 1);
                WriteMask(Entry.Slice(0x28), Mask, Wide);
            }

            public void Group(uint Count, ulong Mask)
            {
                if (!Includes(RelationGroup))
                    return;

                Span<byte> Entry = Next(RelationGroup, 0x48 + (Wide ? 8 : 4));
                if (Entry.IsEmpty)
                    return;

                BinaryPrimitives.WriteUInt16LittleEndian(Entry.Slice(0x08), 1);
                BinaryPrimitives.WriteUInt16LittleEndian(Entry.Slice(0x0A), 1);
                Entry[0x20] = (byte)Count;
                Entry[0x21] = (byte)Count;
                WriteMask(Entry.Slice(0x48), Mask, Wide);
            }
        }

        // CACHE_RELATIONSHIP starts with a CACHE_DESCRIPTOR.
        private static void WriteCacheDescriptor(Span<byte> Target, byte Level, byte Associativity, uint Size, uint Type)
        {
            Target[0] = Level;
            Target[1] = Associativity;
            BinaryPrimitives.WriteUInt16LittleEndian(Target.Slice(2), CacheLineSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(4), Size);
            BinaryPrimitives.WriteUInt32LittleEndian(Target.Slice(8), Type);
        }

        private static void WriteMask(Span<byte> Target, ulong Mask, bool Wide)
        {
            if (Wide)
                BinaryPrimitives.WriteUInt64LittleEndian(Target, Mask);
            else
                BinaryPrimitives.WriteUInt32LittleEndian(Target, (uint)Mask);
        }
    }
}
