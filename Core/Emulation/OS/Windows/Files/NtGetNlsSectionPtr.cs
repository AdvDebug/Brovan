using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtGetNlsSectionPtr : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                uint SectionType = (uint)Instance.WinHelper.GetArg64(0);
                uint SectionData = (uint)Instance.WinHelper.GetArg64(1);
                ulong ContextData = Instance.WinHelper.GetArg64(2);
                ulong SectionPointerPtr = Instance.WinHelper.GetArg64(3);
                ulong SectionSizePtr = Instance.WinHelper.GetArg64(4);

                if (SectionPointerPtr != 0 && !Instance.IsRegionMapped(SectionPointerPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (SectionSizePtr != 0 && !Instance.IsRegionMapped(SectionSizePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (SectionType != 11)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                string Path = $@"C:\Windows\System32\C_{SectionData}.NLS";

                WindowsFileStream Stream = WindowsFileStream.FromGuestPath(Path);
                if (!Stream.TryReadAllBytes(out byte[] Data) || Data.Length == 0)
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                ulong Size = BinaryEmulator.AlignUp((ulong)Data.Length, 0x1000);

                ulong Address = Instance.MapUniqueAddress((uint)Size, MemoryProtection.Read);
                if (Address == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!Instance.WriteMemory(Address, Data))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (SectionPointerPtr != 0)
                    Instance._emulator.WriteMemory(SectionPointerPtr, Address, 8);

                if (SectionSizePtr != 0)
                    Instance._emulator.WriteMemory(SectionSizePtr, (uint)Size);

                Instance.TriggerEventMessage($"[+] NtGetNlsSectionPtr: C_{SectionData}.NLS -> 0x{Address:X} (0x{Size:X}).", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

                uint SectionType = Instance.ReadMemoryUInt(ESP + 4);
                uint SectionData = Instance.ReadMemoryUInt(ESP + 8);
                uint ContextData = Instance.ReadMemoryUInt(ESP + 12);
                uint SectionPointerPtr = Instance.ReadMemoryUInt(ESP + 16);
                uint SectionSizePtr = Instance.ReadMemoryUInt(ESP + 20);

                if (SectionPointerPtr != 0 && !Instance.IsRegionMapped(SectionPointerPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (SectionSizePtr != 0 && !Instance.IsRegionMapped(SectionSizePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (SectionType != 11)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                string Path = $@"C:\Windows\System32\C_{SectionData}.NLS";

                WindowsFileStream Stream = WindowsFileStream.FromGuestPath(Path);
                if (!Stream.TryReadAllBytes(out byte[] Data) || Data.Length == 0)
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                ulong Size = BinaryEmulator.AlignUp((ulong)Data.Length, 0x1000);

                ulong Address = Instance.MapUniqueAddress((uint)Size, MemoryProtection.Read);
                if (Address == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!Instance.WriteMemory(Address, Data))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (SectionPointerPtr != 0)
                    Instance._emulator.WriteMemory(SectionPointerPtr, (uint)Address);

                if (SectionSizePtr != 0)
                    Instance._emulator.WriteMemory(SectionSizePtr, (uint)Size);

                Instance.TriggerEventMessage($"[+] NtGetNlsSectionPtr (x86): C_{SectionData}.NLS -> 0x{Address:X} (0x{Size:X}).", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}
