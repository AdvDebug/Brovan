using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForWorkViaWorkerFactory : IWinSyscall
    {
        private const uint MaxPackets = 0x7FFFFFF;

        // NT: WORKER_FACTORY_DEFERRED_WORK on x64, a message the thread pool asks the kernel to send.
        private const int DeferredWorkSize = 0x18;
        private const ulong DeferredWorkAlignment = 8;
        private const uint DeferredAlpcSend = 0x1;

        // FILE_IO_COMPLETION_INFORMATION.
        internal static bool WritePacket(BinaryEmulator Instance, ulong MiniPackets, uint Index, WinIoCompletionEntry Entry)
        {
            if (Instance.WinHelper.PointerSize == 8)
            {
                Span<byte> Packet = stackalloc byte[0x20];
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x00, 8), Entry.KeyContext);
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x08, 8), Entry.ApcContext);
                BinaryPrimitives.WriteUInt64LittleEndian(Packet.Slice(0x10, 8), (uint)Entry.IoStatus);
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

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg(0);
            ulong MiniPackets = Instance.WinHelper.GetArg(1);
            uint Count = (uint)Instance.WinHelper.GetArg(2);
            ulong PacketsReturnedPtr = Instance.WinHelper.GetArg(3);
            ulong DeferredWork = Instance.WinHelper.GetArg(4);

            if (MiniPackets == 0 || Count == 0 || Count > MaxPackets)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT probes both outputs before it references the factory.
            ulong PacketSize = Instance.WinHelper.PointerSize == 8 ? 0x20u : 0x10u;
            if (!Instance.IsMemoryRangeMapped(MiniPackets, Count * PacketSize)
                || (PacketsReturnedPtr != 0 && !Instance.IsMemoryRangeMapped(PacketsReturnedPtr, 4)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong DeferredMessage = 0;
            ulong DeferredPort = 0;
            uint DeferredFlags = 0;
            if (DeferredWork != 0 && AlpcMessaging.Supported(Instance))
            {
                if ((DeferredWork & (DeferredWorkAlignment - 1)) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                Span<byte> Work = stackalloc byte[DeferredWorkSize];
                if (!Instance.ReadMemory(DeferredWork, Work))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if ((BinaryPrimitives.ReadUInt32LittleEndian(Work.Slice(0x14, 4)) & DeferredAlpcSend) != 0)
                {
                    DeferredMessage = BinaryPrimitives.ReadUInt64LittleEndian(Work.Slice(0x00, 8));
                    DeferredPort = BinaryPrimitives.ReadUInt64LittleEndian(Work.Slice(0x08, 8));
                    DeferredFlags = BinaryPrimitives.ReadUInt32LittleEndian(Work.Slice(0x10, 4));
                }
            }

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
            State.BoundIoCompletion = Completion;
            if (State.WaitCompleted && State.WorkerFactoryWaitActive == false && State.WorkerFactoryHandle == 0)
            {
                NTSTATUS Status = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (DeferredMessage != 0)
                AlpcMessaging.SendDeferred(Instance, DeferredPort, DeferredFlags, DeferredMessage);

            Instance.MaterializeSignaledWaitPackets(Factory.IoCompletionHandle);

            List<WinIoCompletionEntry> Taken = State.WorkerFactoryReservedEntries;
            Taken.Clear();
            Instance.TakeIoCompletionEntries(Completion, Count, Taken);
            uint Removed = (uint)Taken.Count;
            bool Written = true;
            for (int i = 0; i < Taken.Count && Written; i++)
                Written = WritePacket(Instance, MiniPackets, (uint)i, Taken[i]);
            Taken.Clear();

            if (Written && PacketsReturnedPtr != 0)
                Written = Instance._emulator.WriteMemory(PacketsReturnedPtr, Removed, 4);

            if (!Written)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Removed > 0)
                return NTSTATUS.STATUS_SUCCESS;

            long Deadline = Factory.Timeout == 0 ? -1 : Instance.WinHelper.ParseRelativeDeadlineMs(Factory.Timeout);
            if (Factory.Timeout != 0 && Deadline == Instance.EmulatedTickCount64)
                return NTSTATUS.STATUS_TIMEOUT;

            Thread.WaitActive = true;
            Thread.WaitOnSingleHandle(WorkerFactoryHandle);
            Thread.WaitAll = true;
            Thread.WaitDeadline = Deadline;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip();
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
