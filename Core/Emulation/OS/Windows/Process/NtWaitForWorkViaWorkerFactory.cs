using System;
using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForWorkViaWorkerFactory : IWinSyscall
    {
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
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg64(0);
            ulong MiniPackets = Instance.WinHelper.GetArg64(1);
            uint Count = (uint)Instance.WinHelper.GetArg64(2);
            ulong PacketsReturnedPtr = Instance.WinHelper.GetArg64(3);
            ulong DeferredWork = Instance.WinHelper.GetArg64(4);
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
            uint PacketSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 0x20u : 0x10u;
            while (Removed < Count && Completion.Entries.Count > 0)
            {
                WinIoCompletionEntry Entry = Completion.Entries.Dequeue();
                if (Entry.WaitCompletionPacketHandle != 0)
                {
                    WinWaitCompletionPacket Packet = Instance.WinHelper.HandleManager.GetObjectByHandle<WinWaitCompletionPacket>(Entry.WaitCompletionPacketHandle);
                    if (Packet != null)
                    {
                        Packet.Associated = false;
                        Packet.QueuedCompletion = false;
                    }
                }

                ulong Address = MiniPackets + ((ulong)Removed * PacketSize);
                Instance._emulator.WriteMemory(Address + 0x0, Entry.KeyContext, 8);
                Instance._emulator.WriteMemory(Address + 0x8, Entry.ApcContext, 8);
                Instance._emulator.WriteMemory(Address + 0x10, unchecked((ulong)(long)(int)Entry.IoStatus), 8);
                Instance._emulator.WriteMemory(Address + 0x18, Entry.IoStatusInformation, 8);
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
            State.WaitResumeRIP = Instance.ReadRegister(Instance.IPRegister);
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