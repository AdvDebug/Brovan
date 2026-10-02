using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtGetNlsSectionPtr : IWinSyscall
    {
        private const uint PAGE_READONLY = 0x02;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint SectionType = (uint)Instance.WinHelper.GetArg(0);
            uint SectionData = (uint)Instance.WinHelper.GetArg(1);
            ulong ContextData = Instance.WinHelper.GetArg(2);
            ulong SectionPointerPtr = Instance.WinHelper.GetArg(3);
            ulong SectionSizePtr = Instance.WinHelper.GetArg(4);
            uint Width = (uint)Instance.WinHelper.PointerSize;

            // NT: the WOW64 thunk does not probe the caller's size.
            bool SizeIsChecked = SectionSizePtr != 0 && Width == 8;

            if (SectionPointerPtr == 0 && ContextData == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (SectionPointerPtr != 0 && !Instance.IsRegionCommitted(SectionPointerPtr, Width))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (SizeIsChecked && !Instance.IsRegionCommitted(SectionSizePtr, Width))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT: only a kernel caller may ask for the section object.
            if (ContextData != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if (SectionType != 11)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            WinSection Section = Instance.WinHelper.GetNlsSection($@"\NLS\NlsSectionCP{SectionData}", $@"C:\Windows\System32\C_{SectionData}.NLS", out NTSTATUS Status);
            if (Section == null)
                return Status;

            ulong ViewSize = BinaryEmulator.AlignUp(Section.Size, 0x1000);
            Status = NtMapViewOfSection.MapDataView(Instance, Section, 0, ViewSize, 0, PAGE_READONLY, out ulong ViewBase);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.WritePointer(SectionPointerPtr, ViewBase))
            {
                Instance.WinHelper.UnmapViewOfSection(ViewBase);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (SectionSizePtr != 0 && !Instance.WinHelper.WritePointer(SectionSizePtr, ViewSize) && SizeIsChecked)
            {
                Instance.WinHelper.UnmapViewOfSection(ViewBase);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtGetNlsSectionPtr: C_{SectionData}.NLS -> 0x{ViewBase:X} (0x{ViewSize:X}).", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
