using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetEvent : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) => ResolveEvent(Instance, Instance.WinHelper.GetArg(0));

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong EventHandle = Instance.WinHelper.GetArg(0);
            ulong PreviousStatePtr = Instance.WinHelper.GetArg(1);

            return Handle(Instance, EventHandle, PreviousStatePtr, true);
        }

        private static WinEvent? LookUpEvent(BinaryEmulator Instance, ulong EventHandle) =>
            Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.EventModifyState);

        internal static WinSyscallDomain ResolveEvent(BinaryEmulator Instance, ulong EventHandle)
        {
            WinEvent? Ev = LookUpEvent(Instance, EventHandle);
            if (Ev == null)
                return WinSyscallDomain.KernelLock;

            Instance.WinHelper.SetResolvedObject(EventHandle, Ev);
            return WinSyscallDomain.Scheduler;
        }

        internal static NTSTATUS Handle(BinaryEmulator Instance, ulong EventHandle, ulong PreviousStatePtr, bool Signaled)
        {
            if (PreviousStatePtr != 0)
            {
                if (!Instance._emulator.IsRangeMapped(PreviousStatePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WinEvent? Ev = Instance.WinHelper.TakeResolvedObject<WinEvent>(EventHandle) ?? LookUpEvent(Instance, EventHandle);
            if (Ev == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            int Prev;
            using (Ev.EnterStateScope())
            {
                Prev = Ev.Signaled ? 1 : 0;
                Ev.Signaled = Signaled;
            }
            // NT ignores a fault on this write once the event has changed.
            if (PreviousStatePtr != 0)
                Instance._emulator.WriteMemory(PreviousStatePtr, (uint)Prev);

            if (Signaled && Instance.WakeWaitersForObject(Ev))
                Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal class NtResetEvent : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) => NtSetEvent.ResolveEvent(Instance, Instance.WinHelper.GetArg(0));

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong EventHandle = Instance.WinHelper.GetArg(0);
            ulong PreviousStatePtr = Instance.WinHelper.GetArg(1);

            return NtSetEvent.Handle(Instance, EventHandle, PreviousStatePtr, false);
        }
    }

    internal class NtClearEvent : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) => NtSetEvent.ResolveEvent(Instance, Instance.WinHelper.GetArg(0));

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong EventHandle = Instance.WinHelper.GetArg(0);

            return NtSetEvent.Handle(Instance, EventHandle, 0, false);
        }
    }
}
