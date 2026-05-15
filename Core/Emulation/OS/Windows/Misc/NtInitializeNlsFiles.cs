using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtInitializeNlsFiles : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong BaseAddressPtr = Instance.WinHelper.GetArg64(0);
                ulong DefaultLcidPtr = Instance.WinHelper.GetArg64(1);
                ulong CasingSizePtr = Instance.WinHelper.GetArg64(2);
                ulong CurrentVerPtr = Instance.WinHelper.GetArg64(3);

                if (BaseAddressPtr != 0 && !Instance.IsRegionMapped(BaseAddressPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (DefaultLcidPtr != 0 && !Instance.IsRegionMapped(DefaultLcidPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (CasingSizePtr != 0 && !Instance.IsRegionMapped(CasingSizePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                bool CanWriteVer = (CurrentVerPtr != 0 && Instance.IsRegionMapped(CurrentVerPtr, 4));

                const string LocaleNlsPath = @"C:\Windows\System32\locale.nls";
                WindowsFileStream Stream = WindowsFileStream.FromGuestPath(LocaleNlsPath);
                if (!Stream.TryReadAllBytes(out byte[] data) || data.Length < 0x40)
                {
                    return NTSTATUS.STATUS_FILE_INVALID;
                }

                ulong MapSize = BinaryEmulator.AlignUp((ulong)data.Length, 0x1000);
                ulong addr = Instance.MapUniqueAddress((uint)MapSize, MemoryProtection.Read);
                if (addr == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!Instance.WriteMemory(addr, data))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint LCID = 0x0409;

                ulong CasingSize = 0;
                if (data.Length >= 0x14)
                {
                    uint localesOffset = BitConverter.ToUInt32(data, 0x10); // header->locales
                    CasingSize = localesOffset;
                }

                if (BaseAddressPtr != 0) Instance._emulator.WriteMemory(BaseAddressPtr, addr, 8);
                if (DefaultLcidPtr != 0) Instance._emulator.WriteMemory(DefaultLcidPtr, LCID);
                if (CasingSizePtr != 0) Instance._emulator.WriteMemory(CasingSizePtr, CasingSize, 8);
                if (CanWriteVer) Instance._emulator.WriteMemory(CurrentVerPtr, 0u);

                Instance.TriggerEventMessage($"[+] NtInitializeNlsFiles: locale.nls -> 0x{addr:X} (0x{MapSize:X}), LCID=0x{LCID:X}, CasingSize=0x{CasingSize:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint esp = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

                uint BaseAddressPtr = Instance.ReadMemoryUInt(esp + 4);
                uint DefaultLcidPtr = Instance.ReadMemoryUInt(esp + 8);
                uint CasingSizePtr = Instance.ReadMemoryUInt(esp + 12);
                uint CurrentVerPtr = Instance.ReadMemoryUInt(esp + 16); // optional

                if (BaseAddressPtr != 0 && !Instance.IsRegionMapped(BaseAddressPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (DefaultLcidPtr != 0 && !Instance.IsRegionMapped(DefaultLcidPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (CasingSizePtr != 0 && !Instance.IsRegionMapped(CasingSizePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                bool CanWriteVer = (CurrentVerPtr != 0 && Instance.IsRegionMapped(CurrentVerPtr, 4));

                const string LocaleNlsPath = @"C:\Windows\System32\locale.nls";
                WindowsFileStream Stream = WindowsFileStream.FromGuestPath(LocaleNlsPath);
                if (!Stream.TryReadAllBytes(out byte[] data) || data.Length < 0x40)
                {
                    return NTSTATUS.STATUS_FILE_INVALID;
                }

                ulong MapSize = BinaryEmulator.AlignUp((ulong)data.Length, 0x1000);
                ulong addr = Instance.MapUniqueAddress((uint)MapSize, MemoryProtection.Read);
                if (addr == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!Instance.WriteMemory(addr, data))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint LCID = 0x0409;

                ulong CasingSize = 0;
                if (data.Length >= 0x14)
                {
                    uint LocalesOffset = BitConverter.ToUInt32(data, 0x10);
                    CasingSize = LocalesOffset;
                }

                if (BaseAddressPtr != 0) Instance._emulator.WriteMemory(BaseAddressPtr, (uint)addr);
                if (DefaultLcidPtr != 0) Instance._emulator.WriteMemory(DefaultLcidPtr, LCID);
                if (CasingSizePtr != 0) Instance._emulator.WriteMemory(CasingSizePtr, CasingSize, 8);
                if (CanWriteVer) Instance._emulator.WriteMemory(CurrentVerPtr, 0u);

                Instance.TriggerEventMessage($"[+] NtInitializeNlsFiles (x86): locale.nls -> 0x{addr:X} (0x{MapSize:X}), LCID=0x{LCID:X}, CasingSize=0x{CasingSize:X}", LogFlags.Syscall);

                return NTSTATUS.STATUS_SUCCESS;
            }

        }
    }
}