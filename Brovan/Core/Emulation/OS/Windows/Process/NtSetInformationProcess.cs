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

            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.WinHelper.GetArg(1);
            ulong ProcessInformation = Instance.WinHelper.GetArg(2);
            uint ProcessInformationLength = (uint)Instance.WinHelper.GetArg(3);

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessSetInformation, out WinProcess Target);
            if (Status == NTSTATUS.STATUS_ACCESS_DENIED)
                Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessSetLimitedInformation, out Target);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // kernelbase treats a failure here as fatal. Only the priority class of another process is modelled.
            if (Target.PID != Instance.WinHelper.PID)
            {
                if (InfoClass == PROCESSINFOCLASS.ProcessPriorityClass || InfoClass == PROCESSINFOCLASS.ProcessPriorityClassEx)
                    return SetPriorityClass(Instance, Target, ProcessInformation, ProcessInformationLength, InfoClass == PROCESSINFOCLASS.ProcessPriorityClassEx);

                return NTSTATUS.STATUS_SUCCESS;
            }

            switch (InfoClass)
            {
                case PROCESSINFOCLASS.ProcessDefaultHardErrorMode:
                    if (ProcessInformationLength >= sizeof(uint) && Instance.IsRegionMapped(ProcessInformation, sizeof(uint)))
                        Instance.WinHelper.DefaultHardErrorMode = Instance.ReadMemoryUInt(ProcessInformation);

                    return NTSTATUS.STATUS_SUCCESS;

                case PROCESSINFOCLASS.ProcessPriorityClass:
                    return SetPriorityClass(Instance, Target, ProcessInformation, ProcessInformationLength, false);

                case PROCESSINFOCLASS.ProcessPriorityClassEx:
                    return SetPriorityClass(Instance, Target, ProcessInformation, ProcessInformationLength, true);

                // Needs SeDebugPrivilege.
                case PROCESSINFOCLASS.ProcessBreakOnTermination:
                    if (ProcessInformationLength != sizeof(uint))
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                    return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;

                case PROCESSINFOCLASS.ProcessDebugFlags:
                    if (ProcessInformationLength != sizeof(uint))
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(ProcessInformation, sizeof(uint)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Instance.WinHelper.ProcessDebugFlags = Instance.ReadMemoryUInt(ProcessInformation) & 1;
                    return NTSTATUS.STATUS_SUCCESS;

                case PROCESSINFOCLASS.ProcessAffinityMask:
                    return SetAffinityMask(Instance, ProcessInformation, ProcessInformationLength);

                case PROCESSINFOCLASS.ProcessDebugPort:
                case PROCESSINFOCLASS.ProcessPriorityBoost:
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
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] NtSetInformationProcess: {InfoClass} (0x{(uint)InfoClass:X}) not implemented.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_SUCCESS;
            }
        }

        // PROCESS_PRIORITY_CLASS is Foreground, PriorityClass. PROCESS_PRIORITY_CLASS_EX is a USHORT of valid bits,
        // PriorityClass, Foreground.
        private static NTSTATUS SetPriorityClass(BinaryEmulator Instance, WinProcess Process, ulong ProcessInformation, uint ProcessInformationLength, bool Extended)
        {
            const byte PriorityClassRealtime = 4;
            const uint PriorityClassValid = 0x2;
            uint Length = Extended ? 4u : 2u;

            if (ProcessInformationLength != Length)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ProcessInformation, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            byte PriorityClass;
            if (Extended)
            {
                uint Value = Instance.ReadMemoryUInt(ProcessInformation);
                if ((Value & PriorityClassValid) == 0)
                    return NTSTATUS.STATUS_SUCCESS;

                PriorityClass = (byte)(Value >> 16);
            }
            else
            {
                PriorityClass = (byte)(Instance._emulator.ReadMemoryUShort(ProcessInformation) >> 8);
            }

            if (PriorityClass < 1 || PriorityClass > 6)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Needs SeIncreaseBasePriorityPrivilege. kernelbase then falls back to HIGH.
            if (PriorityClass == PriorityClassRealtime)
                return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;

            Process.PriorityClass = PriorityClass;
            if (Process.PID != Instance.WinHelper.PID)
                return NTSTATUS.STATUS_SUCCESS;

            Instance.WinHelper.CurrentPriority = WinSysHelper.PriorityClassBase(PriorityClass);

            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread != null && Thread.State != EmulatedThreadState.Terminated)
                    Instance.WinHelper.ApplyThreadBasePriority(Thread);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS SetAffinityMask(BinaryEmulator Instance, ulong ProcessInformation, uint ProcessInformationLength)
        {
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            if (ProcessInformationLength != PointerSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ProcessInformation, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Mask = Instance.WinHelper.ReadPointer(ProcessInformation);
            if (Mask == 0 || (Mask & ~Instance.WinHelper.ActiveProcessorMask) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance.WinHelper.ProcessAffinityMask = Mask;
            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread != null)
                    Thread.AffinityMask = Mask;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HandleProcessInstrumentationCallback(BinaryEmulator Instance, ulong ProcessInformation, uint ProcessInformationLength)
        {
            ulong Callback;

            // The legacy form passes a pointer to the callback address.
            if (ProcessInformationLength == 8)
            {
                if (!Instance.IsRegionMapped(ProcessInformation, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Callback = Instance.ReadMemoryULong(ProcessInformation);
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

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[!] NtSetInformationProcess: ProcessInstrumentationCallback=0x{Callback:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private NTSTATUS HandleProcessTlsInformation(BinaryEmulator Instance, ulong ProcessInformation, uint ProcessInformationLength)
        {
            const uint ProcessTlsReplaceIndex = 0;
            const uint ProcessTlsReplaceVector = 1;
            const uint ThreadTlsInformationFlagsAssigned = 2;
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;
            const uint HeaderSize = 0x10;
            uint EntrySize = PointerSize == 8 ? 0x18u : 0x0Cu;

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
                            ulong TlsEntryAddress = TlsVector + ((ulong)TlsIndexOrPreviousCount * PointerSize);
                            if (!Instance.IsRegionMapped(TlsEntryAddress, PointerSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            ulong OldTlsData = Instance.WinHelper.ReadPointer(TlsEntryAddress);
                            if (!Instance.WinHelper.WritePointer(TlsEntryAddress, TlsData))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            TlsData = OldTlsData;
                            break;
                        }

                    case ProcessTlsReplaceVector:
                        {
                            ulong NewTlsVector = TlsData;
                            ulong CopySize = (ulong)TlsIndexOrPreviousCount * PointerSize;

                            if (NewTlsVector == 0)
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (CopySize != 0 && (!Instance.IsRegionMapped(TlsVector, CopySize) || !Instance.IsRegionMapped(NewTlsVector, CopySize)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            for (uint VectorIndex = 0; VectorIndex < TlsIndexOrPreviousCount; VectorIndex++)
                            {
                                ulong OldTlsEntry = Instance.WinHelper.ReadPointer(TlsVector + ((ulong)VectorIndex * PointerSize));
                                if (!Instance.WinHelper.WritePointer(NewTlsVector + ((ulong)VectorIndex * PointerSize), OldTlsEntry))
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

            uint Ptr = (uint)Instance.WinHelper.PointerSize;
            if (!Instance.IsRegionMapped(EntryAddress, Ptr == 8 ? 0x18u : 0x0Cu))
                return false;

            Flags = Instance.ReadMemoryUInt(EntryAddress + 0x0);
            TlsData = Instance.WinHelper.ReadPointer(EntryAddress + Ptr);
            ThreadId = Instance.WinHelper.ReadPointer(EntryAddress + Ptr * 2);
            return true;
        }

        private bool WriteThreadTlsInformation(BinaryEmulator Instance, ulong EntryAddress, uint Flags, ulong TlsData, ulong ThreadId)
        {
            uint Ptr = (uint)Instance.WinHelper.PointerSize;
            if (!Instance.IsRegionMapped(EntryAddress, Ptr == 8 ? 0x18u : 0x0Cu))
                return false;

            if (!Instance._emulator.WriteMemory(EntryAddress + 0x0, Flags))
                return false;

            if (!Instance.WinHelper.WritePointer(EntryAddress + Ptr, TlsData))
                return false;

            return Instance.WinHelper.WritePointer(EntryAddress + Ptr * 2, ThreadId);
        }

        private static ulong TlsPointerOffset(BinaryEmulator Instance) => Instance.WinHelper.PointerSize == 8 ? 0x58UL : 0x2CUL;

        private ulong GetThreadTlsVector(BinaryEmulator Instance, EmulatedThread Thread)
        {
            ulong TlsVectorAddress = WinEmulatedThread.GetState(Thread).Teb + TlsPointerOffset(Instance);
            if (!Instance.IsRegionMapped(TlsVectorAddress, (uint)Instance.WinHelper.PointerSize))
                return 0;

            return Instance.WinHelper.ReadPointer(TlsVectorAddress);
        }

        private bool SetThreadTlsVector(BinaryEmulator Instance, EmulatedThread Thread, ulong TlsVector)
        {
            ulong TlsVectorAddress = WinEmulatedThread.GetState(Thread).Teb + TlsPointerOffset(Instance);
            if (!Instance.IsRegionMapped(TlsVectorAddress, (uint)Instance.WinHelper.PointerSize))
                return false;

            return Instance.WinHelper.WritePointer(TlsVectorAddress, TlsVector);
        }
    }
}
