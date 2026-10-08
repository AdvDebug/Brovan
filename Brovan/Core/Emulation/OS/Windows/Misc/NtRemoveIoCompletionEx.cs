using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtRemoveIoCompletionEx : IWinSyscall
    {
        private const uint MaxEntries = 0x7FFFFFF;

        // FILE_IO_COMPLETION_INFORMATION records, then the count.
        internal static bool WriteEntries(BinaryEmulator Instance, ulong InformationPtr, ulong EntriesRemovedPtr, List<WinIoCompletionEntry> Entries)
        {
            for (int i = 0; i < Entries.Count; i++)
            {
                if (!NtWaitForWorkViaWorkerFactory.WritePacket(Instance, InformationPtr, (uint)i, Entries[i]))
                    return false;
            }

            return Instance._emulator.WriteMemory(EntriesRemovedPtr, (uint)Entries.Count, 4);
        }

        private static NTSTATUS ReturnEmpty(BinaryEmulator Instance, ulong EntriesRemovedPtr, NTSTATUS Status)
        {
            return Instance._emulator.WriteMemory(EntriesRemovedPtr, 0u, 4) ? Status : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong IoCompletionHandle = Instance.WinHelper.GetArg(0);
            ulong InformationPtr = Instance.WinHelper.GetArg(1);
            uint Count = (uint)Instance.WinHelper.GetArg(2);
            ulong EntriesRemovedPtr = Instance.WinHelper.GetArg(3);
            ulong TimeoutPtr = Instance.WinHelper.GetArg(4);
            bool Alertable = (byte)Instance.WinHelper.GetArg(5) != 0;

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            bool Wide = Instance.WinHelper.PointerSize == 8;

            // WOW64 refuses a NULL buffer itself. The x64 kernel probes it and faults.
            if (Count == 0 || Count > MaxEntries || (!Wide && InformationPtr == 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Wide && (InformationPtr & 7) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            ulong RecordSize = Wide ? 0x20u : 0x10u;
            if (!Instance.IsMemoryRangeMapped(InformationPtr, Count * RecordSize)
                || !Instance.IsMemoryRangeMapped(EntriesRemovedPtr, 4)
                || !Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS HandleStatus = Instance.WinHelper.ResolveIoCompletionHandle(IoCompletionHandle, out WinIoCompletion Completion);
            if (HandleStatus != NTSTATUS.STATUS_SUCCESS)
                return HandleStatus;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Instance.MaterializeSignaledWaitPackets(IoCompletionHandle);

            if (!Thread.WaitActive)
            {
                bool BoundWithPackets = ReferenceEquals(State.BoundIoCompletion, Completion) && Completion.PendingCount > 0;
                if (!BoundWithPackets && Instance.WinHelper.TryEndWaitWithUserApc(Thread, Alertable))
                    return ReturnEmpty(Instance, EntriesRemovedPtr, NTSTATUS.STATUS_USER_APC);

                State.BoundIoCompletion = Completion;
            }

            List<WinIoCompletionEntry> Taken = State.IoCompletionReservedEntries;
            Taken.Clear();
            Instance.TakeIoCompletionEntries(Completion, Count, Taken);
            if (Taken.Count > 0)
            {
                bool Written = WriteEntries(Instance, InformationPtr, EntriesRemovedPtr, Taken);
                Taken.Clear();

                if (Thread.WaitActive)
                    Instance.WinHelper.ClearWaitState(Thread);

                return Written ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (Thread.WaitActive)
            {
                if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
                {
                    Instance.WinHelper.ClearWaitState(Thread);
                    return ReturnEmpty(Instance, EntriesRemovedPtr, NTSTATUS.STATUS_TIMEOUT);
                }
            }
            else
            {
                long Deadline = Instance.WinHelper.ParseRelativeDeadlineMs(Timeout);
                if (Deadline == Instance.EmulatedTickCount64)
                    return ReturnEmpty(Instance, EntriesRemovedPtr, NTSTATUS.STATUS_TIMEOUT);

                Thread.WaitActive = true;
                Thread.WaitHandles = new List<ulong> { IoCompletionHandle };
                Thread.WaitAll = true;
                Thread.WaitDeadline = Deadline;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_PENDING;
                State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
                State.WaitReturnRIP = State.WaitResumeRIP + 2;
                State.WaitAlertable = Alertable;
                State.ResetIoCompletionWait();
                State.IoCompletionWaitActive = true;
                State.IoCompletionHandle = IoCompletionHandle;
                State.IoCompletionInformationPtr = InformationPtr;
                State.IoCompletionEntriesRemovedPtr = EntriesRemovedPtr;
                State.IoCompletionMaxEntries = Count;
            }

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = Alertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
