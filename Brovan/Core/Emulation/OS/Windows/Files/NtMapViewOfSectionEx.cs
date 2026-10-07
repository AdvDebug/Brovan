using System;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtMapViewOfSectionEx : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const int ExtendedParameterSize = 0x10;

        // MEM_EXTENDED_PARAMETER_TYPE
        private const byte ParameterAddressRequirements = 1;
        private const byte ParameterNumaNode = 2;
        private const byte ParameterAttributeFlags = 5;
        private const byte ParameterImageMachine = 6;
        private const byte MaxParameterType = 6;

        // NT: the types MiMapViewOfSectionExCommon passes to MiCaptureAllocateMapExtendedParameters.
        private const uint MapParameterTypes = (1u << ParameterAddressRequirements) | (1u << ParameterNumaNode) |
            (1u << ParameterAttributeFlags) | (1u << ParameterImageMachine);

        // NT: the attribute flags both the capture and MiMapViewOfSectionExCommon let through.
        private const ulong MapAttributeFlags = 0x220;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SectionHandle = Instance.WinHelper.GetArg(0);
            ulong ProcessHandle = Instance.WinHelper.GetArg(1);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(2);
            ulong SectionOffsetPtr = Instance.WinHelper.GetArg(3);
            ulong ViewSizePtr = Instance.WinHelper.GetArg(4);
            uint AllocationType = (uint)Instance.WinHelper.GetArg(5);
            uint Win32Protect = (uint)Instance.WinHelper.GetArg(6);
            ulong ExtendedParametersPtr = Instance.WinHelper.GetArg(7);
            uint ExtendedParameterCount = (uint)Instance.WinHelper.GetArg(8);

            return NtMapViewOfSection.MapView(Instance, SectionHandle, ProcessHandle, BaseAddressPtr, SectionOffsetPtr, ViewSizePtr,
                AllocationType, Win32Protect, ExtendedParametersPtr, ExtendedParameterCount, true);
        }

        // NT: MiCaptureAllocateMapExtendedParameters, then MiMapExParametersInitialize.
        internal static NTSTATUS ReadPlacement(BinaryEmulator Instance, ulong ParametersPtr, uint Count, uint AllocationType, ulong RequestedBase,
            ulong RequestedSize, out NtAllocateVirtualMemory.AddressRequirements Window, out bool ReplacePlaceholder)
        {
            Window = NtAllocateVirtualMemory.AddressRequirements.None;
            ReplacePlaceholder = (AllocationType & NtMapViewOfSection.MemReplacePlaceholder) != 0;

            NTSTATUS Status = CaptureParameters(Instance, ParametersPtr, Count, out ulong Lowest, out ulong Highest, out ulong Alignment);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Alignment != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong Granularity = WinSysHelper.AllocationGranularity;
            if (ReplacePlaceholder)
            {
                if (Lowest != 0 || Highest != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Granularity = PageSize;
            }

            if ((Lowest & (Granularity - 1)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (RequestedBase != 0 && (Lowest != 0 || Highest != 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Highest != 0 && (Highest > NtWow64GetNativeSystemInformation.NativeMaximumUserModeAddress || ((Highest + 1) & (PageSize - 1)) != 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong Ceiling = Highest != 0 ? Highest : Instance.MaxAddress;
            if (Lowest >= Ceiling || (RequestedSize != 0 && Ceiling - Lowest + 1 < RequestedSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((AllocationType & NtMapViewOfSection.NumaNodeMask) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Lowest != 0 || Highest != 0)
            {
                Window.Lowest = Lowest;
                Window.Highest = Math.Min(Ceiling, Instance.MaxAddress);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS CaptureParameters(BinaryEmulator Instance, ulong ParametersPtr, uint Count, out ulong Lowest, out ulong Highest, out ulong Alignment)
        {
            Lowest = 0;
            Highest = 0;
            Alignment = 0;

            if (Count == 0)
                return ParametersPtr != 0 ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_SUCCESS;

            if (ParametersPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (PointerSize == 8 && (ParametersPtr & 7) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Parameter = stackalloc byte[ExtendedParameterSize];
            uint Seen = 0;

            for (uint Index = 0; Index < Count; Index++)
            {
                if (!Instance._emulator.ReadMemory(ParametersPtr + Index * ExtendedParameterSize, Parameter))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ulong Header = BinaryPrimitives.ReadUInt64LittleEndian(Parameter);
                ulong Value = BinaryPrimitives.ReadUInt64LittleEndian(Parameter.Slice(8));
                byte Type = (byte)Header;

                if (Header > byte.MaxValue || Type == 0 || Type > MaxParameterType)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                uint Bit = 1u << Type;
                if ((MapParameterTypes & Bit) == 0 || (Seen & Bit) != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Seen |= Bit;

                switch (Type)
                {
                    case ParameterAddressRequirements:
                        {
                            ulong Address = PointerSize == 8 ? Value : (uint)Value;
                            if (PointerSize == 8 && (Address & 7) != 0)
                                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                            Span<byte> Requirements = stackalloc byte[24];
                            Requirements = Requirements.Slice(0, (int)PointerSize * 3);
                            if (!Instance._emulator.ReadMemory(Address, Requirements))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            Lowest = ReadPointerField(Requirements, 0, PointerSize);
                            Highest = ReadPointerField(Requirements, 1, PointerSize);
                            Alignment = ReadPointerField(Requirements, 2, PointerSize);
                            break;
                        }

                    case ParameterNumaNode:
                        {
                            ulong Node = Value > uint.MaxValue ? Value & ~(1UL << 63) : Value;
                            if (Node > uint.MaxValue || Node == uint.MaxValue)
                                return NTSTATUS.STATUS_INVALID_PARAMETER;

                            // One node, numbered 0, as SystemNumaProcessorMap reports.
                            if (Node != 0)
                                return NTSTATUS.STATUS_INVALID_PARAMETER;
                            break;
                        }

                    case ParameterAttributeFlags:
                        if ((Value & ~MapAttributeFlags) != 0)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;
                        break;

                    case ParameterImageMachine:
                        if (Value > ushort.MaxValue)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;
                        break;
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong ReadPointerField(ReadOnlySpan<byte> Fields, int Index, uint PointerSize)
        {
            return PointerSize == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(Fields.Slice(Index * 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(Fields.Slice(Index * 4));
        }
    }
}
