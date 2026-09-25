using System.Buffers.Binary;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            uint ThreadInformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong ThreadInformation = Instance.WinHelper.GetArg(2);
            uint ThreadInformationLength = (uint)Instance.WinHelper.GetArg(3);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(4);

            if (ReturnLengthPtr != 0 && !Instance.IsRegionMapped(ReturnLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            EmulatedThread ThreadObj = ResolveThreadFromHandle(Instance, ThreadHandle);
            if (ThreadObj == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (ThreadInformation != 0 && ThreadInformationLength != 0)
            {
                if (!Instance.IsRegionMapped(ThreadInformation, ThreadInformationLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            bool Is64 = Instance.WinHelper.PointerSize == 8;

            void WriteReturnLength(uint Length)
            {
                if (ReturnLengthPtr != 0)
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Length);
            }

            NTSTATUS ValidateOutputBuffer(uint RequiredSize)
            {
                WriteReturnLength(RequiredSize);

                if (ThreadInformation == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ThreadInformationLength < RequiredSize)
                    return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                if (!Instance.IsRegionMapped(ThreadInformation, RequiredSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS WriteExact(Span<byte> Record)
            {
                if (ThreadInformationLength != (uint)Record.Length)
                    return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                if (ThreadInformation == 0 || !Instance.WriteMemory(ThreadInformation, Record))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                WriteReturnLength((uint)Record.Length);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Affinity = ThreadObj.AffinityMask & Instance.WinHelper.ProcessAffinityMask;
            if (Affinity == 0)
                Affinity = Instance.WinHelper.ProcessAffinityMask;

            switch ((THREADINFOCLASS)ThreadInformationClass)
            {
                case THREADINFOCLASS.ThreadBasicInformation:
                    {
                        uint RequiredSize = Is64 ? 0x30u : 0x1Cu;
                        NTSTATUS Status = ValidateOutputBuffer(RequiredSize);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Slice(0, (int)RequiredSize).Clear();

                        uint ExitStatus = ThreadObj.State == EmulatedThreadState.Terminated
                            ? unchecked((uint)ThreadObj.ExitCode)
                            : (uint)NTSTATUS.STATUS_PENDING;

                        // NT reports BasePriority as the increment over the process class.
                        int BaseIncrement = Instance.WinHelper.QueryThreadBasePriorityIncrement(ThreadObj);

                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), ExitStatus);

                        if (Is64)
                        {
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), WinEmulatedThread.GetState(ThreadObj).Teb);
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), Instance.WinHelper.PID);
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), (ulong)ThreadObj.ThreadId);
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x20, 8), Affinity);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), (uint)ThreadObj.EffectivePriority);
                            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x2C, 4), BaseIncrement);
                        }
                        else
                        {
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), (uint)WinEmulatedThread.GetState(ThreadObj).Teb);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), (uint)Instance.WinHelper.PID);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x0C, 4), ThreadObj.ThreadId);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10, 4), (uint)Affinity);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14, 4), (uint)ThreadObj.EffectivePriority);
                            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x18, 4), BaseIncrement);
                        }

                        if (!Instance.WriteMemory(ThreadInformation, Buffer.Slice(0, (int)RequiredSize)))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadTimes:
                    {
                        Instance.WinHelper.GetThreadTimes(ThreadObj, out long CreateTime, out long ExitTime, out long KernelTime, out long UserTime);

                        Span<byte> Times = stackalloc byte[0x20];
                        BinaryPrimitives.WriteInt64LittleEndian(Times.Slice(0x00, 8), CreateTime);
                        BinaryPrimitives.WriteInt64LittleEndian(Times.Slice(0x08, 8), ExitTime);
                        BinaryPrimitives.WriteInt64LittleEndian(Times.Slice(0x10, 8), KernelTime);
                        BinaryPrimitives.WriteInt64LittleEndian(Times.Slice(0x18, 8), UserTime);
                        return WriteExact(Times);
                    }

                case THREADINFOCLASS.ThreadAmILastThread:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(4);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        uint IsLast = HasOtherLiveThread(Instance, ThreadObj) ? 0u : 1u;
                        if (!Instance._emulator.WriteMemory(ThreadInformation, IsLast))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadQuerySetWin32StartAddress:
                    {
                        NTSTATUS Status = ValidateOutputBuffer((uint)Instance.WinHelper.PointerSize);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance.WinHelper.WritePointer(ThreadInformation, ThreadObj.StartAddress))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadAffinityMask:
                    {
                        NTSTATUS Status = ValidateOutputBuffer((uint)Instance.WinHelper.PointerSize);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance.WinHelper.WritePointer(ThreadInformation, Affinity))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadPriorityBoost:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(4);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance._emulator.WriteMemory(ThreadInformation, ThreadObj.DisablePriorityBoost ? 1u : 0u))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadIsIoPending:
                case THREADINFOCLASS.ThreadDynamicCodePolicyInfo:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(4);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance._emulator.WriteMemory(ThreadInformation, 0u))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadIsTerminated:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(4);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        uint IsTerminated = ThreadObj.State == EmulatedThreadState.Terminated ? 1u : 0u;
                        if (!Instance._emulator.WriteMemory(ThreadInformation, IsTerminated))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadUmsInformation:
                    {
                        NTSTATUS Status = ValidateOutputBuffer((uint)Instance.WinHelper.PointerSize);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance.WinHelper.WritePointer(ThreadInformation, 0UL))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadHideFromDebugger:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(1);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance.WinHelper.WriteByte(ThreadInformation, WinEmulatedThread.GetState(ThreadObj).HiddenFromDebugger ? (byte)1 : (byte)0))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadIdealProcessorEx:
                    {
                        // PROCESSOR_NUMBER: Group, Number, Reserved.
                        Span<byte> Processor = stackalloc byte[4];
                        Processor.Clear();
                        Processor[2] = (byte)(WinEmulatedThread.GetState(ThreadObj).IdealProcessor % Instance.WinHelper.ProcessorCount);
                        return WriteExact(Processor);
                    }

                case THREADINFOCLASS.ThreadGroupInformation:
                    {
                        Span<byte> Group = stackalloc byte[Is64 ? 0x10 : 0x0C];
                        Group.Clear();
                        if (Is64)
                            BinaryPrimitives.WriteUInt64LittleEndian(Group, Affinity);
                        else
                            BinaryPrimitives.WriteUInt32LittleEndian(Group, (uint)Affinity);
                        return WriteExact(Group);
                    }

                case THREADINFOCLASS.ThreadSuspendCount:
                    {
                        Span<byte> Count = stackalloc byte[4];
                        BinaryPrimitives.WriteInt32LittleEndian(Count, ThreadObj.SuspendCount);
                        return WriteExact(Count);
                    }

                case THREADINFOCLASS.ThreadCycleTime:
                    {
                        Instance.WinHelper.GetThreadTimes(ThreadObj, out _, out _, out long KernelTime, out long UserTime);
                        ulong Cycles = WinSysHelper.TimeToCycles(KernelTime + UserTime);

                        Span<byte> CycleTime = stackalloc byte[0x10];
                        BinaryPrimitives.WriteUInt64LittleEndian(CycleTime.Slice(0x00, 8), Cycles);
                        BinaryPrimitives.WriteUInt64LittleEndian(CycleTime.Slice(0x08, 8), Cycles);
                        return WriteExact(CycleTime);
                    }

                case THREADINFOCLASS.ThreadNameInformation:
                    {
                        string Description = WinEmulatedThread.GetState(ThreadObj).Description ?? string.Empty;
                        uint HeaderSize = Is64 ? 0x10u : 0x08u;
                        uint NameBytes = (uint)Description.Length * 2;
                        uint RequiredSize = HeaderSize + NameBytes;

                        WriteReturnLength(RequiredSize);
                        if (ThreadInformation == 0 || ThreadInformationLength < RequiredSize)
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                        Span<byte> Record = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Record.Clear();
                        BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x00, 2), (ushort)NameBytes);
                        BinaryPrimitives.WriteUInt16LittleEndian(Record.Slice(0x02, 2), (ushort)NameBytes);

                        if (NameBytes != 0)
                        {
                            if (Is64)
                                BinaryPrimitives.WriteUInt64LittleEndian(Record.Slice(0x08, 8), ThreadInformation + HeaderSize);
                            else
                                BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(0x04, 4), (uint)(ThreadInformation + HeaderSize));

                            Encoding.Unicode.GetBytes(Description.AsSpan(), Record.Slice((int)HeaderSize, (int)NameBytes));
                        }

                        return Instance.WriteMemory(ThreadInformation, Record) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                default:
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!] NtQueryInformationThread: Unsupported class=0x{ThreadInformationClass:X}, len=0x{ThreadInformationLength:X}", LogFlags.Issues);
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
            }
        }

        /// <summary>
        /// Resolves a native thread handle, including both 32-bit and 64-bit current-thread pseudo handles.
        /// </summary>
        private static EmulatedThread ResolveThreadFromHandle(BinaryEmulator Instance, ulong ThreadHandle)
        {
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
                return Instance.CurrentThread;

            return Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
        }

        /// <summary>
        /// Checks whether another process thread is still alive for ThreadAmILastThread.
        /// </summary>
        private static bool HasOtherLiveThread(BinaryEmulator Instance, EmulatedThread CurrentThread)
        {
            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread == null)
                    continue;

                if (CurrentThread != null && Thread.ThreadId == CurrentThread.ThreadId)
                    continue;

                if (Thread.State != EmulatedThreadState.Terminated)
                    return true;
            }

            return false;
        }
    }
}
