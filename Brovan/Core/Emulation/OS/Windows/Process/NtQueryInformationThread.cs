using System.Buffers.Binary;
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

            switch ((THREADINFOCLASS)ThreadInformationClass)
            {
                case THREADINFOCLASS.ThreadBasicInformation:
                    {
                        bool Is64 = Instance.WinHelper.PointerSize == 8;
                        uint RequiredSize = Is64 ? 0x30u : 0x1Cu;
                        NTSTATUS Status = ValidateOutputBuffer(RequiredSize);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RequiredSize);
                        Buffer.Slice(0, (int)RequiredSize).Clear();

                        uint ExitStatus = ThreadObj.State == EmulatedThreadState.Terminated
                            ? unchecked((uint)ThreadObj.ExitCode)
                            : (uint)NTSTATUS.STATUS_PENDING;

                        BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), ExitStatus);

                        if (Is64)
                        {
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x08, 8), WinEmulatedThread.GetState(ThreadObj).Teb);
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x10, 8), Instance.WinHelper.PID);
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x18, 8), (ulong)ThreadObj.ThreadId);
                            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(0x20, 8), 1UL);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x28, 4), (uint)ThreadObj.EffectivePriority);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x2C, 4), (uint)ThreadObj.BasePriority);
                        }
                        else
                        {
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), (uint)WinEmulatedThread.GetState(ThreadObj).Teb);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), (uint)Instance.WinHelper.PID);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x0C, 4), ThreadObj.ThreadId);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x10, 4), 1u);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x14, 4), (uint)ThreadObj.EffectivePriority);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), (uint)ThreadObj.BasePriority);
                        }

                        if (!Instance.WriteMemory(ThreadInformation, Buffer.Slice(0, (int)RequiredSize)))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
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
                        NTSTATUS Status = ValidateOutputBuffer(8);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance._emulator.WriteMemory(ThreadInformation, ThreadObj.StartAddress))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadAffinityMask:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(8);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance._emulator.WriteMemory(ThreadInformation, ThreadObj.AffinityMask == 0 ? 1UL : ThreadObj.AffinityMask))
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
                        NTSTATUS Status = ValidateOutputBuffer(8);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance._emulator.WriteMemory(ThreadInformation, 0UL))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadHideFromDebugger:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(1);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance.WinHelper.WriteByte(ThreadInformation, 0))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadIdealProcessorEx:
                    {
                        NTSTATUS Status = ValidateOutputBuffer(0x28);
                        if (Status != NTSTATUS.STATUS_SUCCESS)
                            return Status;

                        if (!Instance.WinHelper.WriteZeroMemory(ThreadInformation, 0x28))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        return NTSTATUS.STATUS_SUCCESS;
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
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle) || ThreadHandle == 0xFFFFFFFEu)
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
