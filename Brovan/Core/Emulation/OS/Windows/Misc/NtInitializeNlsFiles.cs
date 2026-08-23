using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtInitializeNlsFiles : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(0);
            ulong DefaultLcidPtr = Instance.WinHelper.GetArg(1);
            ulong CasingSizePtr = Instance.WinHelper.GetArg(2);

            if (BaseAddressPtr != 0 && !Instance.IsRegionMapped(BaseAddressPtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (DefaultLcidPtr != 0 && !Instance.IsRegionMapped(DefaultLcidPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (CasingSizePtr != 0 && !Instance.IsRegionMapped(CasingSizePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            const string LocaleNlsPath = @"C:\Windows\System32\locale.nls";

            WindowsFileStream Stream = WindowsFileStream.FromGuestPath(LocaleNlsPath, false, true);
            if (!Stream.TryReadAllBytes(out byte[] Data) || Data.Length < 0x40)
                return NTSTATUS.STATUS_FILE_INVALID;

            ulong MapSize = BinaryEmulator.AlignUp((ulong)Data.Length, 0x1000);
            ulong Address = Instance.MapUniqueAddress((uint)MapSize, MemoryProtection.Read);
            if (Address == 0)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (!Instance.WriteMemory(Address, Data))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            const uint LCID = 0x0409;

            ulong CasingSize = 0;
            if (Data.Length >= 0x14)
                CasingSize = BitConverter.ToUInt32(Data, 0x10);

            if (BaseAddressPtr != 0) Instance.WinHelper.WritePointer(BaseAddressPtr, Address);
            if (DefaultLcidPtr != 0) Instance.WinHelper.WriteUInt32(DefaultLcidPtr, LCID);
            if (CasingSizePtr != 0) Instance.WinHelper.WriteUInt64(CasingSizePtr, CasingSize);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtInitializeNlsFiles: locale.nls -> 0x{Address:X} (0x{MapSize:X}), LCID=0x{LCID:X}, CasingSize=0x{CasingSize:X}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
