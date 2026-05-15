using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandle = Instance.WinHelper.GetArg64(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg64(1);

                return Handle(Instance, EventHandle, PreviousStatePtr, true);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandle = Instance.WinHelper.GetArg32(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg32(1);

                return Handle(Instance, EventHandle, PreviousStatePtr, true);
            }

            return Instance.WinUnimplemented;
        }

        internal static NTSTATUS Handle(BinaryEmulator Instance, ulong EventHandle, ulong PreviousStatePtr, bool Signaled)
        {
            if (PreviousStatePtr != 0)
            {
                if (!Instance.IsRegionMapped(PreviousStatePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WinEvent Ev = Instance.WinHelper.GetEventByHandle(EventHandle, (AccessMask)0x0002);
            if (Ev == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            int Prev = Ev.Signaled ? 1 : 0;
            Ev.Signaled = Signaled;
            if (PreviousStatePtr != 0)
            {
                if (!Instance._emulator.WriteMemory(PreviousStatePtr, (uint)Prev))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (Signaled && Instance.WakeWorkerFactoryWaitersForObject(EventHandle))
                Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal class NtResetEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandle = Instance.WinHelper.GetArg64(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg64(1);

                return NtSetEvent.Handle(Instance, EventHandle, PreviousStatePtr, false);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandle = Instance.WinHelper.GetArg32(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg32(1);

                return NtSetEvent.Handle(Instance, EventHandle, PreviousStatePtr, false);
            }

            return Instance.WinUnimplemented;
        }
    }

    internal class NtClearEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandle = Instance.WinHelper.GetArg64(0);

                return NtSetEvent.Handle(Instance, EventHandle, 0, false);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandle = Instance.WinHelper.GetArg32(0);

                return NtSetEvent.Handle(Instance, EventHandle, 0, false);
            }

            return Instance.WinUnimplemented;
        }
    }
}
