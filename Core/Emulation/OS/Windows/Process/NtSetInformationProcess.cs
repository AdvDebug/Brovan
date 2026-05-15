using System;
using System.Collections.Generic;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.WinHelper.GetArg64(1);
            ulong ProcessInformation = Instance.WinHelper.GetArg64(2);
            uint ProcessInformationLength = (uint)Instance.WinHelper.GetArg64(3);

            bool CurrentProcess = ProcessHandle == ulong.MaxValue;

            if (!CurrentProcess)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            switch (InfoClass)
            {
                case PROCESSINFOCLASS.ProcessDebugPort:
                case PROCESSINFOCLASS.ProcessDefaultHardErrorMode:
                case PROCESSINFOCLASS.ProcessAffinityMask:
                case PROCESSINFOCLASS.ProcessPriorityBoost:
                case PROCESSINFOCLASS.ProcessDebugFlags:
                case PROCESSINFOCLASS.ProcessIoPriority:
                case PROCESSINFOCLASS.ProcessExecuteFlags:
                case PROCESSINFOCLASS.ProcessAffinityUpdateMode:
                case PROCESSINFOCLASS.ProcessTokenVirtualizationEnabled:
                case PROCESSINFOCLASS.ProcessConsoleHostProcess:
                case PROCESSINFOCLASS.ProcessFaultInformation:
                case PROCESSINFOCLASS.ProcessHandleCheckingMode:
                case PROCESSINFOCLASS.ProcessRaiseUMExceptionOnInvalidHandleClose:
                    return NTSTATUS.STATUS_SUCCESS;

                case PROCESSINFOCLASS.ProcessTlsInformation:
                    return HandleProcessTlsInformation(Instance, ProcessInformation, ProcessInformationLength);

                case PROCESSINFOCLASS.ProcessInstrumentationCallback:
                    return HandleProcessInstrumentationCallback(Instance, ProcessInformation, ProcessInformationLength);

                default:
                    Instance.TriggerEventMessage($"[!] NtSetInformationProcess: {InfoClass} (0x{(uint)InfoClass:X}) not implemented.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_SUCCESS;
            }
        }

        private NTSTATUS HandleProcessInstrumentationCallback(BinaryEmulator Instance, ulong ProcessInformation, uint ProcessInformationLength)
        {
            ulong Callback;

            if (ProcessInformationLength == 8)
            {
                Callback = ProcessInformation;
            }
            else if (ProcessInformationLength == 16)
            {
                if (!Instance.IsRegionMapped(ProcessInformation, 16))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint Version = Instance.ReadMemoryUInt(ProcessInformation + 0x00);
                uint Reserved = Instance.ReadMemoryUInt(ProcessInformation + 0x04);
                if (Version != 0 || Reserved != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Callback = Instance.ReadMemoryULong(ProcessInformation + 0x08);
            }
            else
            {
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
            }

            WinProcess CurrentProcess = Instance.WinHelper.WinProcesses.FirstOrDefault(Process => Process.PID == Instance.WinHelper.PID);
            if (CurrentProcess != null)
                CurrentProcess.InstrumentationCallback = Callback;

            Instance.TriggerEventMessage($"[!] NtSetInformationProcess: ProcessInstrumentationCallback=0x{Callback:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HandleProcessTlsInformation(BinaryEmulator Instance, ulong ProcessInformation, uint ProcessInformationLength)
        {
            const uint ProcessTlsReplaceIndex = 0;
            const uint ProcessTlsReplaceVector = 1;
            const uint ThreadTlsInformationFlagsAssigned = 2;
            const uint HeaderSize = 0x10;
            const uint EntrySize = 0x18;

            if (ProcessInformation == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ProcessInformationLength < HeaderSize + EntrySize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (((ProcessInformationLength - HeaderSize) % EntrySize) != 0)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ProcessInformation, ProcessInformationLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Flags = Instance.ReadMemoryUInt(ProcessInformation + 0x0);
            uint OperationType = Instance.ReadMemoryUInt(ProcessInformation + 0x4);
            uint ThreadDataCount = Instance.ReadMemoryUInt(ProcessInformation + 0x8);
            uint TlsIndexOrPreviousCount = Instance.ReadMemoryUInt(ProcessInformation + 0xC);

            if (Flags != 0)
                return Flags == 1 ? NTSTATUS.STATUS_INVALID_PARAMETER : NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (OperationType != ProcessTlsReplaceIndex && OperationType != ProcessTlsReplaceVector)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint BufferThreadDataCount = (ProcessInformationLength - HeaderSize) / EntrySize;
            if (ThreadDataCount == 0 || ThreadDataCount > BufferThreadDataCount)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            List<EmulatedThread> Threads = GetProcessTlsThreads(Instance);
            ulong ThreadDataAddress = ProcessInformation + HeaderSize;
            uint ThreadDataIndex = 0;

            foreach (EmulatedThread Thread in Threads)
            {
                if (ThreadDataIndex >= ThreadDataCount)
                    break;

                ulong TlsVector = GetThreadTlsVector(Instance, Thread);
                if (TlsVector == 0)
                    continue;

                ulong EntryAddress = ThreadDataAddress + ((ulong)ThreadDataIndex * EntrySize);
                if (!TryReadThreadTlsInformation(Instance, EntryAddress, out uint EntryFlags, out ulong TlsData, out ulong ThreadId))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (EntryFlags != 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                switch (OperationType)
                {
                    case ProcessTlsReplaceIndex:
                        {
                            ulong TlsEntryAddress = TlsVector + ((ulong)TlsIndexOrPreviousCount * 8UL);
                            if (!Instance.IsRegionMapped(TlsEntryAddress, 8))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            ulong OldTlsData = Instance.ReadMemoryULong(TlsEntryAddress);
                            if (!Instance._emulator.WriteMemory(TlsEntryAddress, TlsData))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            TlsData = OldTlsData;
                            break;
                        }

                    case ProcessTlsReplaceVector:
                        {
                            ulong NewTlsVector = TlsData;
                            ulong CopySize = (ulong)TlsIndexOrPreviousCount * 8UL;

                            if (NewTlsVector == 0)
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (CopySize != 0 && (!Instance.IsRegionMapped(TlsVector, CopySize) || !Instance.IsRegionMapped(NewTlsVector, CopySize)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            for (uint VectorIndex = 0; VectorIndex < TlsIndexOrPreviousCount; VectorIndex++)
                            {
                                ulong OldTlsEntry = Instance.ReadMemoryULong(TlsVector + ((ulong)VectorIndex * 8UL));
                                if (!Instance._emulator.WriteMemory(NewTlsVector + ((ulong)VectorIndex * 8UL), OldTlsEntry))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }

                            if (!SetThreadTlsVector(Instance, Thread, NewTlsVector))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            TlsData = TlsVector;
                            ThreadId = Thread.ThreadId;
                            break;
                        }
                }

                EntryFlags = ThreadTlsInformationFlagsAssigned;
                if (!WriteThreadTlsInformation(Instance, EntryAddress, EntryFlags, TlsData, ThreadId))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ThreadDataIndex++;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private List<EmulatedThread> GetProcessTlsThreads(BinaryEmulator Instance)
        {
            List<EmulatedThread> Threads = new List<EmulatedThread>();

            if (Instance.CurrentThreadId >= 0 && Instance.Threads.TryGetValue((uint)Instance.CurrentThreadId, out EmulatedThread CurrentThread) &&
                CurrentThread != null && CurrentThread.State != EmulatedThreadState.Terminated)
            {
                Threads.Add(CurrentThread);
            }

            foreach (KeyValuePair<uint, EmulatedThread> Pair in Instance.Threads.OrderBy(Thread => Thread.Key))
            {
                EmulatedThread Thread = Pair.Value;
                if (Thread == null || Thread.State == EmulatedThreadState.Terminated)
                    continue;

                if (Instance.CurrentThreadId >= 0 && Thread.ThreadId == (uint)Instance.CurrentThreadId)
                    continue;

                Threads.Add(Thread);
            }

            return Threads;
        }

        private bool TryReadThreadTlsInformation(BinaryEmulator Instance, ulong EntryAddress, out uint Flags, out ulong TlsData, out ulong ThreadId)
        {
            Flags = 0;
            TlsData = 0;
            ThreadId = 0;

            if (!Instance.IsRegionMapped(EntryAddress, 0x18))
                return false;

            Flags = Instance.ReadMemoryUInt(EntryAddress + 0x0);
            TlsData = Instance.ReadMemoryULong(EntryAddress + 0x8);
            ThreadId = Instance.ReadMemoryULong(EntryAddress + 0x10);
            return true;
        }

        private bool WriteThreadTlsInformation(BinaryEmulator Instance, ulong EntryAddress, uint Flags, ulong TlsData, ulong ThreadId)
        {
            if (!Instance.IsRegionMapped(EntryAddress, 0x18))
                return false;

            if (!Instance._emulator.WriteMemory(EntryAddress + 0x0, Flags))
                return false;

            if (!Instance._emulator.WriteMemory(EntryAddress + 0x8, TlsData))
                return false;

            return Instance._emulator.WriteMemory(EntryAddress + 0x10, ThreadId);
        }

        const ulong TebThreadLocalStoragePointerOffset = 0x58;

        private ulong GetThreadTlsVector(BinaryEmulator Instance, EmulatedThread Thread)
        {
            ulong TlsVectorAddress = WinEmulatedThread.GetState(Thread).Teb + TebThreadLocalStoragePointerOffset;
            if (!Instance.IsRegionMapped(TlsVectorAddress, 8))
                return 0;

            return Instance.ReadMemoryULong(TlsVectorAddress);
        }

        private bool SetThreadTlsVector(BinaryEmulator Instance, EmulatedThread Thread, ulong TlsVector)
        {
            ulong TlsVectorAddress = WinEmulatedThread.GetState(Thread).Teb + TebThreadLocalStoragePointerOffset;
            if (!Instance.IsRegionMapped(TlsVectorAddress, 8))
                return false;

            return Instance._emulator.WriteMemory(TlsVectorAddress, TlsVector);
        }
    }
}
