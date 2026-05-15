using System;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAreMappedFilesTheSame : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Address1 = Instance.WinHelper.GetArg64(0);
            ulong Address2 = Instance.WinHelper.GetArg64(1);

            if (Address1 == 0 || Address2 == 0)
                return NTSTATUS.STATUS_INVALID_ADDRESS;

            MemoryRegion? Region1 = FindRegion(Instance, Address1);
            MemoryRegion? Region2 = FindRegion(Instance, Address2);

            if (!Region1.HasValue || !Region2.HasValue)
                return NTSTATUS.STATUS_INVALID_ADDRESS;

            if (Region1.Value.AllocationBase == Region2.Value.AllocationBase)
                return NTSTATUS.STATUS_SUCCESS;

            WinModule View1 = Instance.WinHelper.FindMappedImageViewByAddress(Address1);
            WinModule View2 = Instance.WinHelper.FindMappedImageViewByAddress(Address2);

            if (View1 == null || View2 == null)
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

            if (View1.ImageSectionId != 0 && View1.ImageSectionId == View2.ImageSectionId)
            {
                Instance.TriggerEventMessage($"[+] NtAreMappedFilesTheSame: 0x{Address1:X} and 0x{Address2:X} both map ImageSectionId=0x{View1.ImageSectionId:X}.", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string Path1 = !string.IsNullOrEmpty(View1.CanonicalImagePath)
                ? View1.CanonicalImagePath
                : Instance.WinHelper.CanonicalizeImagePath(!string.IsNullOrEmpty(View1.Path) ? View1.Path : View1.Name);

            string Path2 = !string.IsNullOrEmpty(View2.CanonicalImagePath)
                ? View2.CanonicalImagePath
                : Instance.WinHelper.CanonicalizeImagePath(!string.IsNullOrEmpty(View2.Path) ? View2.Path : View2.Name);

            if (!string.IsNullOrEmpty(Path1) && !string.IsNullOrEmpty(Path2) &&
                string.Equals(Path1, Path2, StringComparison.OrdinalIgnoreCase))
            {
                Instance.TriggerEventMessage($"[+] NtAreMappedFilesTheSame: 0x{Address1:X} and 0x{Address2:X} both map {Path1}.", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.TriggerEventMessage($"[+] NtAreMappedFilesTheSame: 0x{Address1:X} ({Path1}) and 0x{Address2:X} ({Path2}) are different images.", LogFlags.Syscall);
            return NTSTATUS.STATUS_NOT_SAME_DEVICE;
        }

        private static MemoryRegion? FindRegion(BinaryEmulator Instance, ulong Address)
        {
            if (Instance.TryFindMemoryRegion(Address, out MemoryRegion Region))
                return Region;

            return null;
        }
    }
}
