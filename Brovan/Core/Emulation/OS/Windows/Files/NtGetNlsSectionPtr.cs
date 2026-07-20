using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtGetNlsSectionPtr : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint SectionType = (uint)Instance.WinHelper.GetArg(0);
            uint SectionData = (uint)Instance.WinHelper.GetArg(1);
            ulong SectionPointerPtr = Instance.WinHelper.GetArg(3);
            ulong SectionSizePtr = Instance.WinHelper.GetArg(4);

            if (SectionPointerPtr != 0 && !Instance.IsRegionMapped(SectionPointerPtr, (uint)Instance.WinHelper.PointerSize))
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
                Instance.WinHelper.WritePointer(SectionPointerPtr, Address);

            if (SectionSizePtr != 0)
                Instance.WinHelper.WriteUInt32(SectionSizePtr, (uint)Size);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtGetNlsSectionPtr: C_{SectionData}.NLS -> 0x{Address:X} (0x{Size:X}).", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
