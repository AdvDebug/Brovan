using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAccessCheck : IWinSyscall
    {
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint GenericExecute = 0x20000000;
        private const uint GenericAll = 0x10000000;

        private static uint ApplyGenericMapping(uint DesiredAccess, uint MapRead, uint MapWrite, uint MapExecute, uint MapAll)
        {
            uint Mapped = DesiredAccess;

            if ((Mapped & GenericRead) != 0)
            {
                Mapped &= ~GenericRead;
                Mapped |= MapRead;
            }

            if ((Mapped & GenericWrite) != 0)
            {
                Mapped &= ~GenericWrite;
                Mapped |= MapWrite;
            }

            if ((Mapped & GenericExecute) != 0)
            {
                Mapped &= ~GenericExecute;
                Mapped |= MapExecute;
            }

            if ((Mapped & GenericAll) != 0)
            {
                Mapped &= ~GenericAll;
                Mapped |= MapAll;
            }

            return Mapped;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong SecurityDescriptor = Instance.WinHelper.GetArg64(0);
                ulong ClientToken = Instance.WinHelper.GetArg64(1);
                uint DesiredAccess = (uint)Instance.WinHelper.GetArg64(2, true);
                ulong GenericMappingPtr = Instance.WinHelper.GetArg64(3);
                ulong PrivilegeSet = Instance.WinHelper.GetArg64(4);
                ulong PrivilegeSetLengthPtr = Instance.WinHelper.GetArg64(5);
                ulong GrantedAccessPtr = Instance.WinHelper.GetArg64(6);
                ulong AccessStatusPtr = Instance.WinHelper.GetArg64(7);

                if (GrantedAccessPtr == 0 || AccessStatusPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(GrantedAccessPtr, 4) || !Instance.IsRegionMapped(AccessStatusPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (PrivilegeSetLengthPtr != 0 && !Instance.IsRegionMapped(PrivilegeSetLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint MapRead = 0;
                uint MapWrite = 0;
                uint MapExecute = 0;
                uint MapAll = 0;

                if (GenericMappingPtr != 0)
                {
                    if (!Instance.IsRegionMapped(GenericMappingPtr, 16))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    MapRead = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0x0);
                    MapWrite = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0x4);
                    MapExecute = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0x8);
                    MapAll = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0xC);
                }

                uint GrantedAccess = ApplyGenericMapping(DesiredAccess, MapRead, MapWrite, MapExecute, MapAll);

                Instance._emulator.WriteMemory(GrantedAccessPtr, GrantedAccess);
                Instance._emulator.WriteMemory(AccessStatusPtr, (uint)NTSTATUS.STATUS_SUCCESS);

                if (PrivilegeSetLengthPtr != 0)
                    Instance._emulator.WriteMemory(PrivilegeSetLengthPtr, 0u);

                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint SecurityDescriptor32 = Instance.WinHelper.GetArg32(0);
                uint ClientToken32 = Instance.WinHelper.GetArg32(1);
                uint DesiredAccess = Instance.WinHelper.GetArg32(2);
                uint GenericMappingPtr32 = Instance.WinHelper.GetArg32(3);
                uint PrivilegeSet32 = Instance.WinHelper.GetArg32(4);
                uint PrivilegeSetLengthPtr32 = Instance.WinHelper.GetArg32(5);
                uint GrantedAccessPtr32 = Instance.WinHelper.GetArg32(6);
                uint AccessStatusPtr32 = Instance.WinHelper.GetArg32(7);

                ulong GenericMappingPtr = GenericMappingPtr32;
                ulong PrivilegeSetLengthPtr = PrivilegeSetLengthPtr32;
                ulong GrantedAccessPtr = GrantedAccessPtr32;
                ulong AccessStatusPtr = AccessStatusPtr32;

                if (GrantedAccessPtr == 0 || AccessStatusPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(GrantedAccessPtr, 4) || !Instance.IsRegionMapped(AccessStatusPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (PrivilegeSetLengthPtr != 0 && !Instance.IsRegionMapped(PrivilegeSetLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint MapRead = 0;
                uint MapWrite = 0;
                uint MapExecute = 0;
                uint MapAll = 0;

                if (GenericMappingPtr != 0)
                {
                    if (!Instance.IsRegionMapped(GenericMappingPtr, 16))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    MapRead = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0x0);
                    MapWrite = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0x4);
                    MapExecute = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0x8);
                    MapAll = Instance._emulator.ReadMemoryUInt(GenericMappingPtr + 0xC);
                }

                uint GrantedAccess = ApplyGenericMapping(DesiredAccess, MapRead, MapWrite, MapExecute, MapAll);

                Instance._emulator.WriteMemory(GrantedAccessPtr, GrantedAccess);
                Instance._emulator.WriteMemory(AccessStatusPtr, (uint)NTSTATUS.STATUS_SUCCESS);

                if (PrivilegeSetLengthPtr != 0)
                    Instance._emulator.WriteMemory(PrivilegeSetLengthPtr, 0u);

                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}
