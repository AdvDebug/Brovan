using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtInitializeNlsFiles : IWinSyscall
    {
        private const uint PAGE_READONLY = 0x02;
        private const uint DefaultLcid = 0x0409;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(0);
            ulong DefaultLcidPtr = Instance.WinHelper.GetArg(1);

            if (!Instance.IsRegionCommitted(BaseAddressPtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionCommitted(DefaultLcidPtr, sizeof(uint)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinSection Section = Instance.WinHelper.GetNlsSection(null, @"C:\Windows\System32\locale.nls", out NTSTATUS Status);
            if (Section == null)
                return Status;

            ulong ViewSize = BinaryEmulator.AlignUp(Section.Size, 0x1000);
            Status = NtMapViewOfSection.MapDataView(Instance, Section, 0, ViewSize, 0, PAGE_READONLY, out ulong ViewBase);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.WritePointer(BaseAddressPtr, ViewBase) || !Instance.WinHelper.WriteUInt32(DefaultLcidPtr, DefaultLcid))
            {
                Instance.WinHelper.UnmapViewOfSection(ViewBase);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtInitializeNlsFiles: locale.nls -> 0x{ViewBase:X} (0x{ViewSize:X}), LCID=0x{DefaultLcid:X}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
