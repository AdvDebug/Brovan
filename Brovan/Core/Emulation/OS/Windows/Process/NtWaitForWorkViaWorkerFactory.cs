using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForWorkViaWorkerFactory : IWinSyscall
    {
        // FILE_IO_COMPLETION_INFORMATION.
        internal static bool WritePacket(BinaryEmulator Instance, ulong MiniPackets, uint Index, WinIoCompletionEntry Entry)
        {
            if (Instance.WinHelper.PointerSize == 8)
            {
                Span<byte> Packet = stackalloc byte[0x20];
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x00, 8), Entry.KeyContext);
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x08, 8), Entry.ApcContext);
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x10, 8), unchecked((ulong)(long)(int)Entry.IoStatus));
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x18, 8), Entry.IoStatusInformation);
                return Instance._emulator.WriteMemory(MiniPackets + (ulong)Index * 0x20, Packet);
            }

            Span<byte> Packet32 = stackalloc byte[0x10];
            BinaryPrimitives.WriteUInt32LittleEndian(Packet32.Slice(0x00, 4), (uint)Entry.KeyContext);
            BinaryPrimitives.WriteUInt32LittleEndian(Packet32.Slice(0x04, 4), (uint)Entry.ApcContext);
            BinaryPrimitives.WriteUInt32LittleEndian(Packet32.Slice(0x08, 4), (uint)Entry.IoStatus);
            BinaryPrimitives.WriteUInt32LittleEndian(Packet32.Slice(0x0C, 4), (uint)Entry.IoStatusInformation);
            return Instance._emulator.WriteMemory(MiniPackets + (ulong)Index * 0x10, Packet32);
        }

        private static long ParseTimeoutDeadline(BinaryEmulator Instance, long Timeout)
        {
            if (Timeout == 0)
                return -1;

            long Milliseconds;
            if (Timeout < 0)
                Milliseconds = ((-Timeout) + 9999) / 10000;
            else
            {
                long NowFileTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
                if (Timeout <= NowFileTime)
                    return Instance.EmulatedTickCount64;

                Milliseconds = ((Timeout - NowFileTime) + 9999) / 10000;
            }

            if (Milliseconds < 0)
                Milliseconds = 0;

            return Instance.CreateEmulatedDeadlineMilliseconds(Milliseconds);
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg(0);
            ulong MiniPackets = Instance.WinHelper.GetArg(1);
            uint Count = (uint)Instance.WinHelper.GetArg(2);
            ulong PacketsReturnedPtr = Instance.WinHelper.GetArg(3);
            ulong DeferredWork = Instance.WinHelper.GetArg(4);
            _ = DeferredWork;

            if (MiniPackets == 0 || Count == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WinWorkerFactory Factory = WorkerFactoryHelper.GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinIoCompletion Completion = WorkerFactoryHelper.GetIoCompletion(Instance, Factory.IoCompletionHandle);
            if (Completion == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitCompleted && State.WorkerFactoryWaitActive == false && State.WorkerFactoryHandle == 0)
            {
                NTSTATUS Status = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            Instance.MaterializeSignaledWaitPackets(Factory.IoCompletionHandle);

            uint Removed = 0;
            while (Removed < Count && Completion.PendingCount > 0)
            {
                WinIoCompletionEntry Entry = Completion.Take();
                WorkerFactoryHelper.OnIoCompletionEntryDequeued(Instance, Entry);

                if (Entry.WaitCompletionPacketHandle != 0)
                {
                    WinWaitCompletionPacket Packet = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(Entry.WaitCompletionPacketHandle);
                    if (Packet != null)
                    {
                        Packet.Associated = false;
                        Packet.QueuedCompletion = false;
                    }
                }

                WritePacket(Instance, MiniPackets, Removed, Entry);
                Removed++;
            }

            if (PacketsReturnedPtr != 0)
            {
                if (!Instance.IsRegionMapped(PacketsReturnedPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PacketsReturnedPtr, Removed, 4);
            }

            if (Removed > 0)
            {
                State.WorkerFactoryReservedEntries?.Clear();
                return NTSTATUS.STATUS_SUCCESS;
            }

            long Deadline = ParseTimeoutDeadline(Instance, Factory.Timeout);
            if (Factory.Timeout != 0 && Deadline == Instance.EmulatedTickCount64)
                return NTSTATUS.STATUS_TIMEOUT;

            Thread.WaitActive = true;
            Thread.WaitHandles = new List<ulong> { WorkerFactoryHandle };
            Thread.WaitAll = true;
            Thread.WaitDeadline = Deadline;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
            State.WaitReturnRIP = State.WaitResumeRIP + 2;
            State.WaitAlertable = false;
            State.WorkerFactoryReservedEntries?.Clear();
            State.WorkerFactoryWaitActive = true;
            State.WorkerFactoryHandle = WorkerFactoryHandle;
            State.WorkerFactoryMiniPackets = MiniPackets;
            State.WorkerFactoryPacketsReturned = PacketsReturnedPtr;
            State.WorkerFactoryMaxPackets = Count;

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = false;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }
    }
}
