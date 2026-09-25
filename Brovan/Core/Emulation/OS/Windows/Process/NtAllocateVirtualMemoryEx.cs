using System;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateVirtualMemoryEx : IWinSyscall
    {
        private const ulong AllocationGranularity = 0x10000;
        private const uint MaxExtendedParameters = 16;
        private const int ExtendedParameterSize = 0x10;

        // MEM_EXTENDED_PARAMETER_TYPE
        private const byte ParameterAddressRequirements = 1;
        private const byte ParameterNumaNode = 2;
        private const byte ParameterPartitionHandle = 3;
        private const byte ParameterUserPhysicalHandle = 4;
        private const byte ParameterAttributeFlags = 5;
        private const byte ParameterImageMachine = 6;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg(2);
            uint AllocationType = (uint)Instance.WinHelper.GetArg(3);
            uint Protect = (uint)Instance.WinHelper.GetArg(4);
            ulong ExtendedParametersPtr = Instance.WinHelper.GetArg(5);
            uint ExtendedParameterCount = (uint)Instance.WinHelper.GetArg(6);

            NTSTATUS Status = ReadRequirements(Instance, ExtendedParametersPtr, ExtendedParameterCount, out NtAllocateVirtualMemory.AddressRequirements Requirements);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // Address requirements only steer an allocation whose address the system picks.
            if (Requirements.Limited && BaseAddressPtr != 0 && Instance.IsRegionMapped(BaseAddressPtr, (uint)Instance.WinHelper.PointerSize) &&
                Instance.WinHelper.ReadPointer(BaseAddressPtr) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NtAllocateVirtualMemory.AllocateCommon(Instance, ProcessHandle, BaseAddressPtr, RegionSizePtr, AllocationType, Protect, Requirements, (uint)Instance.WinHelper.PointerSize);
        }

        // MEM_EXTENDED_PARAMETER is 16 bytes on both architectures. NUMA node and attribute flags only tune placement.
        private static NTSTATUS ReadRequirements(BinaryEmulator Instance, ulong ParametersPtr, uint Count, out NtAllocateVirtualMemory.AddressRequirements Requirements)
        {
            Requirements = NtAllocateVirtualMemory.AddressRequirements.None;

            if (Count == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (ParametersPtr == 0 || Count > MaxExtendedParameters)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Parameters = stackalloc byte[(int)(MaxExtendedParameters * ExtendedParameterSize)];
            Parameters = Parameters.Slice(0, (int)Count * ExtendedParameterSize);
            if (!Instance._emulator.ReadMemory(ParametersPtr, Parameters))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Seen = 0;
            for (int Index = 0; Index < Count; Index++)
            {
                Span<byte> Parameter = Parameters.Slice(Index * ExtendedParameterSize, ExtendedParameterSize);
                byte Type = Parameter[0];
                ulong Value = BinaryPrimitives.ReadUInt64LittleEndian(Parameter.Slice(8, 8));

                if (Type == 0 || Type > ParameterImageMachine || (Seen & (1u << Type)) != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Seen |= 1u << Type;

                switch (Type)
                {
                    case ParameterAddressRequirements:
                        {
                            NTSTATUS Status = ReadAddressRequirements(Instance, Instance.WinHelper.PointerSize == 8 ? Value : (uint)Value, ref Requirements);
                            if (Status != NTSTATUS.STATUS_SUCCESS)
                                return Status;
                            break;
                        }

                    case ParameterNumaNode:
                    case ParameterAttributeFlags:
                    case ParameterImageMachine:
                        break;

                    case ParameterPartitionHandle:
                    case ParameterUserPhysicalHandle:
                        return NTSTATUS.STATUS_NOT_SUPPORTED;
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // MEM_ADDRESS_REQUIREMENTS fields are all pointer-sized.
        private static NTSTATUS ReadAddressRequirements(BinaryEmulator Instance, ulong Address, ref NtAllocateVirtualMemory.AddressRequirements Requirements)
        {
            if (Address == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (!Instance.IsRegionMapped(Address, PointerSize * 3))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Lowest = Instance.WinHelper.ReadPointer(Address);
            ulong Highest = Instance.WinHelper.ReadPointer(Address + PointerSize);
            ulong Alignment = Instance.WinHelper.ReadPointer(Address + PointerSize * 2);

            if (Alignment != 0 && (Alignment < AllocationGranularity || (Alignment & (Alignment - 1)) != 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((Lowest & (AllocationGranularity - 1)) != 0 || (Highest != 0 && ((Highest + 1) & (AllocationGranularity - 1)) != 0) ||
                (Highest != 0 && Highest <= Lowest))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Requirements.Lowest = Lowest;
            Requirements.Highest = Highest != 0 ? Highest : ulong.MaxValue;
            Requirements.Alignment = Alignment;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
