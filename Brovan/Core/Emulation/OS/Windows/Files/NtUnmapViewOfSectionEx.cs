using System;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtUnmapViewOfSectionEx : IWinSyscall
    {
        private const uint MemUnmapWithTransientBoost = 0x1;
        private const uint MemPreservePlaceholder = 0x2;

        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) =>
            Instance.WinHelper.ResolveAddressSpaceCall(Instance.WinHelper.GetArg(0), AccessMask.ProcessVMOperation);

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                ulong BaseAddress = Instance.WinHelper.GetArg(1);
                uint Flags = (uint)Instance.WinHelper.GetArg(2);

                return UnmapView(Instance, ProcessHandle, BaseAddress, Flags, nameof(NtUnmapViewOfSectionEx));
            }
            else
            {
                uint ProcessHandle = Instance.WinHelper.GetArg32(0);
                uint BaseAddress = Instance.WinHelper.GetArg32(1);
                uint Flags = Instance.WinHelper.GetArg32(2);

                return UnmapView(Instance, ProcessHandle, BaseAddress, Flags, nameof(NtUnmapViewOfSectionEx));
            }
        }

        internal static NTSTATUS UnmapView(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddress, uint Flags, string SyscallName)
        {
            if ((Flags & ~(MemUnmapWithTransientBoost | MemPreservePlaceholder)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if (Instance.WinHelper.TakeOrResolveProcess(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process) != NTSTATUS.STATUS_SUCCESS
                || Process.PID != Instance.WinHelper.PID)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinSection? Release = null;
            try
            {
                // NT: only a view that replaced a placeholder turns back into one, and only from its base.
                if ((Flags & MemPreservePlaceholder) != 0)
                    return UnmapToPlaceholder(Instance, BaseAddress, out Release);

                if (!Unmap(Instance, BaseAddress, out Release))
                    return NTSTATUS.STATUS_NOT_MAPPED_VIEW;
            }
            finally
            {
                ReleaseAfterUnmap(Instance, Release);
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
            {
                if (Flags == 0 && string.Equals(SyscallName, nameof(NtUnmapViewOfSection), StringComparison.Ordinal))
                    Instance.TriggerEventMessage($"[+] NtUnmapViewOfSection: Base=0x{BaseAddress:X}", LogFlags.Syscall);
                else
                    Instance.TriggerEventMessage($"[+] {SyscallName}: Base=0x{BaseAddress:X}, Flags=0x{Flags:X}.", LogFlags.Syscall);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool Unmap(BinaryEmulator Instance, ulong BaseAddress, out WinSection? Release)
        {
            WinSysHelper.ViewUnmap Outcome = Instance.WinHelper.TryUnmapView(BaseAddress, out Release);
            if (Outcome == WinSysHelper.ViewUnmap.NeedsKernelLock)
            {
                WindowsGuest.SyscallDomainStats.FellBack(WindowsGuest.SyscallDomainStats.Reason.ViewUnmap);
                using (Instance.EnterKernelLockScope())
                    Outcome = Instance.WinHelper.TryUnmapView(BaseAddress, out Release);
            }

            return Outcome == WinSysHelper.ViewUnmap.Unmapped;
        }

        private static NTSTATUS UnmapToPlaceholder(BinaryEmulator Instance, ulong BaseAddress, out WinSection? Release)
        {
            Release = null;
            using RankedLock.Scope AddressHold = Instance.AddressSpace.Hold();
            if (!Instance.WinHelper.TryFindSectionView(BaseAddress, out WinSectionView View) || !View.FromPlaceholder || View.Base != BaseAddress)
            {
                bool IsView = Instance.TryFindMemoryRegion(BaseAddress, out MemoryRegion Region) && Instance.WinHelper.IsViewAddress(BaseAddress, Region);
                return IsView ? NTSTATUS.STATUS_CONFLICTING_ADDRESSES : NTSTATUS.STATUS_NOT_MAPPED_VIEW;
            }

            if (Instance.WinHelper.TryUnmapView(View.Base, out Release) != WinSysHelper.ViewUnmap.Unmapped)
                return NTSTATUS.STATUS_NOT_MAPPED_VIEW;

            if (!Instance.ReservePlaceholder(View.Base, View.Size))
            {
                Utils.LogError($"[NtUnmapViewOfSectionEx] View at 0x{View.Base:X} size 0x{View.Size:X} was unmapped but its placeholder could not be restored.");
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // The caller holds no address space scope, so taking KernelLock keeps the lock order.
        private static void ReleaseAfterUnmap(BinaryEmulator Instance, WinSection? Release)
        {
            if (Release == null || !Instance.WinHelper.MayRelease(Release))
                return;

            if (!Instance.KernelLockCovered)
                WindowsGuest.SyscallDomainStats.FellBack(WindowsGuest.SyscallDomainStats.Reason.SectionRelease);
            using (Instance.EnterKernelLockScope())
                Instance.WinHelper.ReleaseSectionIfUnreferenced(Release);
        }
    }
}
