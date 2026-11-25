using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtClose : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        // Only an object whose last close runs nothing closes without KernelLock.
        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.GetArg(0);
            IHandleObject? Object = Instance.WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (Object == null || WinSysHelper.ClassifyClose(Object) != WinSysHelper.CloseTail.None)
                return WinSyscallDomain.KernelLock;

            Instance.WinHelper.SetResolvedObject(Handle, Object);
            return WinSyscallDomain.Self;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.GetArg(0);

            if (HandleManager.IsCurrentProcessPseudoHandle(Handle) || HandleManager.IsCurrentThreadPseudoHandle(Handle))
                return NTSTATUS.STATUS_SUCCESS;

            NTSTATUS Status = Close(Instance, Handle);
            if (Status == NTSTATUS.STATUS_INVALID_HANDLE && (Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[!] NtClose: received invalid handle 0x{Handle:X}.", LogFlags.Syscall);

            return Status;
        }

        private static NTSTATUS Close(BinaryEmulator Instance, ulong Handle)
        {
            IHandleObject? Resolved = Instance.WinHelper.TakeResolvedObject<IHandleObject>(Handle);
            if (Resolved != null)
            {
                if (Instance.WinHelper.TryCloseResolved(Handle, Resolved, out NTSTATUS Status))
                    return Status;

                if (!Instance.KernelLockCovered)
                    WindowsGuest.SyscallDomainStats.FellBack(WindowsGuest.SyscallDomainStats.Reason.HandleChanged);
            }

            using RankedLock.Scope KernelScope = Instance.EnterKernelLockScope();
            if (!Instance.WinHelper.HandleExists(Handle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if ((Instance.WinHelper.HandleManager.GetHandleFlags(Handle) & ObjectHandleFlags.ProtectFromClose) != 0)
                return NTSTATUS.STATUS_HANDLE_NOT_CLOSABLE;

            Instance.WinHelper.CloseHandle(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
