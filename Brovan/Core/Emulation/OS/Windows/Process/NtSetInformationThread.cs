using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtSetInformationThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            int ThreadInformationClassValue = (int)Instance.WinHelper.GetArg64(1);
            ulong ThreadInformationPtr = Instance.WinHelper.GetArg64(2);
            uint ThreadInformationLength = (uint)Instance.WinHelper.GetArg64(3);

            return HandleCommon(Instance, ThreadHandle, ThreadInformationClassValue, ThreadInformationPtr, ThreadInformationLength);
        }

        private NTSTATUS Handle32(BinaryEmulator Instance)
        {

            uint ThreadHandle = (uint)Instance.WinHelper.GetArg(0);
            int ThreadInformationClassValue = (int)Instance.WinHelper.GetArg(1);
            uint ThreadInformationPtr = (uint)Instance.WinHelper.GetArg(2);
            uint ThreadInformationLength = (uint)Instance.WinHelper.GetArg(3);

            return HandleCommon(Instance, ThreadHandle, ThreadInformationClassValue, ThreadInformationPtr, ThreadInformationLength);
        }

        private NTSTATUS HandleCommon(BinaryEmulator Instance, ulong ThreadHandle, int ThreadInformationClassValue, ulong ThreadInformationPtr, uint ThreadInformationLength)
        {
            EmulatedThread Thread = ResolveThreadFromHandle(Instance, ThreadHandle);
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            THREADINFOCLASS InfoClass = (THREADINFOCLASS)ThreadInformationClassValue;
            switch (InfoClass)
            {
                case THREADINFOCLASS.ThreadPriority:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < 4)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        // An absolute priority. Real-time values need SeIncreaseBasePriorityPrivilege.
                        int Priority = (int)Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        if (Priority < 1 || Priority > 31)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (Priority > 15)
                            return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;

                        Thread.DynamicBoost = Math.Clamp(Priority - Thread.BasePriority, -16, 16);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadAffinityMask:
                    {
                        uint PointerSize = (uint)Instance.WinHelper.PointerSize;

                        if (ThreadInformationPtr == 0 || ThreadInformationLength < PointerSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, PointerSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        ulong AffinityMask = Instance.WinHelper.ReadPointer(ThreadInformationPtr);

                        if (AffinityMask == 0 || (AffinityMask & ~Instance.WinHelper.ProcessAffinityMask) != 0)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        Thread.AffinityMask = AffinityMask;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadGroupInformation:
                    {
                        uint PointerSize = (uint)Instance.WinHelper.PointerSize;
                        uint GroupSize = PointerSize == 8 ? 0x10u : 0x0Cu;

                        if (ThreadInformationPtr == 0 || ThreadInformationLength != GroupSize)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, GroupSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        ulong AffinityMask = Instance.WinHelper.ReadPointer(ThreadInformationPtr);
                        ushort Group = (ushort)Instance._emulator.ReadMemoryUInt(ThreadInformationPtr + PointerSize);

                        if (Group != 0 || AffinityMask == 0 || (AffinityMask & ~Instance.WinHelper.ProcessAffinityMask) != 0)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        Thread.AffinityMask = AffinityMask;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadIdealProcessorEx:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength != 4)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        // NT writes the previous ideal processor back into the same buffer.
                        uint Requested = Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        ushort Group = (ushort)Requested;
                        byte Number = (byte)(Requested >> 16);
                        if (Group != 0 || Number >= Instance.WinHelper.ProcessorCount)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        uint Previous = (uint)SetIdealProcessor(Instance, Thread, Number) << 16;
                        return Instance.WinHelper.WriteUInt32(ThreadInformationPtr, Previous) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                case THREADINFOCLASS.ThreadIdealProcessor:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength != 4)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        // MAXIMUM_PROCESSORS only queries. NT returns the ideal processor in place of a status.
                        uint Number = Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        if (Number == (uint)(Instance.WinHelper.PointerSize * 8))
                            return (NTSTATUS)WinEmulatedThread.GetState(Thread).IdealProcessor;

                        if (Number >= Instance.WinHelper.ProcessorCount)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        return (NTSTATUS)SetIdealProcessor(Instance, Thread, (byte)Number);
                    }

                case THREADINFOCLASS.ThreadBasePriority:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < 4)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        int Increment = (int)Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        bool Saturated = Increment == 16 || Increment == -16;
                        if (!Saturated && (Increment < -2 || Increment > 2))
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        WindowsThreadState PriorityState = WinEmulatedThread.GetState(Thread);
                        PriorityState.PrioritySaturation = Saturated ? Math.Sign(Increment) : 0;
                        PriorityState.PriorityIncrement = Saturated ? 0 : Increment;
                        Instance.WinHelper.ApplyThreadBasePriority(Thread);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadHideFromDebugger:
                    {
                        if (ThreadInformationLength != 0)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        WinEmulatedThread.GetState(Thread).HiddenFromDebugger = true;
                        if ((Instance.Settings.Flags & LogFlags.Suspicious) != 0)
                            Instance.TriggerEventMessage($"[{Thread.ThreadId}] Thread Hide From Debugger.", LogFlags.Suspicious);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadBreakOnTermination:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < 4)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        uint Value = Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        //Thread.BreakOnTermination = Value != 0;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadPriorityBoost:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < 4)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        uint DisablePriorityBoost = Instance.ReadMemoryUInt(ThreadInformationPtr);
                        Thread.DisablePriorityBoost = DisablePriorityBoost != 0;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadNameInformation:
                    {
                        uint UsSize = (uint)(Instance.WinHelper.PointerSize * 2);
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < UsSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.WinHelper.TryReadUnicodeString(ThreadInformationPtr, out string Name, out NTSTATUS NameStatus))
                            return NameStatus;

                        Thread.Name = Name;
                        WinEmulatedThread.GetState(Thread).Description = Name;
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                case THREADINFOCLASS.ThreadImpersonationToken:
                    {
                        int HandleSize = Instance.WinHelper.PointerSize;

                        if (ThreadInformationPtr == 0 || ThreadInformationLength < (uint)HandleSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, (uint)HandleSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        ulong TokenHandleValue = Instance.WinHelper.ReadPointer(ThreadInformationPtr);

                        WindowsThreadState State = WinEmulatedThread.GetState(Thread);
                        if (TokenHandleValue == 0)
                        {
                            State.ImpersonationTokenHandle = 0;
                            State.ImpersonationToken = null;
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                        if (!Instance.WinHelper.HandleManager.HandleExists(TokenHandleValue, HandleType.TokenHandle))
                            return NTSTATUS.STATUS_INVALID_HANDLE;

                        WinToken Token = Instance.WinHelper.HandleManager.GetObjectByHandle<WinToken>(TokenHandleValue);
                        if (Token == null)
                            return NTSTATUS.STATUS_INVALID_HANDLE;

                        State.ImpersonationTokenHandle = unchecked((int)TokenHandleValue);
                        State.ImpersonationToken = Token;
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                case THREADINFOCLASS.ThreadZeroTlsCell:
                    {
                        return HandleThreadZeroTlsCell(Instance, ThreadInformationPtr, ThreadInformationLength);
                    }

                case THREADINFOCLASS.ThreadSetTlsArrayAddress:
                    {
                        return HandleThreadSetTlsArrayAddress(Instance, Thread, ThreadInformationPtr, ThreadInformationLength);
                    }

                case THREADINFOCLASS.ThreadSchedulerSharedDataSlot:
                    {
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                default:
                    if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                        Instance.TriggerEventMessage($"[!] NtSetInformationThread called with unsupported info class: 0x{InfoClass:X}", LogFlags.Important);
                    return NTSTATUS.STATUS_INVALID_INFO_CLASS;
            }
        }


        private static NTSTATUS HandleThreadZeroTlsCell(BinaryEmulator Instance, ulong ThreadInformationPtr, uint ThreadInformationLength)
        {
            if (ThreadInformationPtr == 0 || ThreadInformationLength < 4)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint TlsCell = Instance.ReadMemoryUInt(ThreadInformationPtr);

            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread == null)
                    continue;

                if (!ZeroTlsCell(Instance, Thread, TlsCell))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleThreadSetTlsArrayAddress(BinaryEmulator Instance, EmulatedThread Thread, ulong ThreadInformationPtr, uint ThreadInformationLength)
        {
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;

            if (ThreadInformationPtr == 0 || ThreadInformationLength < PointerSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ThreadInformationPtr, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong TlsArrayAddress = Instance.WinHelper.ReadPointer(ThreadInformationPtr);

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            ulong TlsPointerAddress = Teb + (PointerSize == 8 ? 0x58UL : 0x2CUL);

            if (!Instance.IsRegionMapped(TlsPointerAddress, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Instance.WinHelper.WritePointer(TlsPointerAddress, TlsArrayAddress)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static bool ZeroTlsCell(BinaryEmulator Instance, EmulatedThread Thread, uint TlsCell)
        {
            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            if (Teb == 0)
                return true;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                const uint TlsMinimumAvailable = 64;
                const uint TlsExpansionSlots = 1024;
                const ulong TlsSlotsOffset = 0x1480;
                const ulong TlsExpansionSlotsOffset = 0x1780;

                if (TlsCell < TlsMinimumAvailable)
                {
                    ulong SlotAddress = Teb + TlsSlotsOffset + ((ulong)TlsCell * 8UL);
                    return !Instance.IsRegionMapped(SlotAddress, 8) || Instance._emulator.WriteMemory(SlotAddress, 0UL);
                }

                if (TlsCell >= TlsMinimumAvailable + TlsExpansionSlots)
                    return true;

                ulong ExpansionSlotsAddress = Teb + TlsExpansionSlotsOffset;
                if (!Instance.IsRegionMapped(ExpansionSlotsAddress, 8))
                    return true;

                ulong ExpansionSlots = Instance.ReadMemoryULong(ExpansionSlotsAddress);
                if (ExpansionSlots == 0)
                    return true;

                ulong SlotAddress2 = ExpansionSlots + (((ulong)TlsCell - TlsMinimumAvailable) * 8UL);
                return !Instance.IsRegionMapped(SlotAddress2, 8) || Instance._emulator.WriteMemory(SlotAddress2, 0UL);
            }

            if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                const uint TlsMinimumAvailable = 64;
                const uint TlsExpansionSlots = 1024;
                const ulong TlsSlotsOffset = 0xE10;
                const ulong TlsExpansionSlotsOffset = 0xF94;

                if (TlsCell < TlsMinimumAvailable)
                {
                    ulong SlotAddress = Teb + TlsSlotsOffset + ((ulong)TlsCell * 4UL);
                    return !Instance.IsRegionMapped(SlotAddress, 4) || Instance._emulator.WriteMemory(SlotAddress, 0u);
                }

                if (TlsCell >= TlsMinimumAvailable + TlsExpansionSlots)
                    return true;

                ulong ExpansionSlotsAddress = Teb + TlsExpansionSlotsOffset;
                if (!Instance.IsRegionMapped(ExpansionSlotsAddress, 4))
                    return true;

                uint ExpansionSlots = Instance.ReadMemoryUInt(ExpansionSlotsAddress);
                if (ExpansionSlots == 0)
                    return true;

                ulong SlotAddress2 = ExpansionSlots + (((ulong)TlsCell - TlsMinimumAvailable) * 4UL);
                return !Instance.IsRegionMapped(SlotAddress2, 4) || Instance._emulator.WriteMemory(SlotAddress2, 0u);
            }

            return true;
        }

        // GetThreadIdealProcessorEx on the calling thread reads TEB.CurrentIdealProcessor.
        private static byte SetIdealProcessor(BinaryEmulator Instance, EmulatedThread Thread, byte Number)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            byte Previous = State.IdealProcessor;
            State.IdealProcessor = Number;

            if (State.Teb != 0)
                Instance.WinHelper.WriteUInt32(State.Teb + (Instance.WinHelper.PointerSize == 8 ? 0x1744UL : 0xF74UL), (uint)Number << 16);

            return Previous;
        }

        private static EmulatedThread ResolveThreadFromHandle(BinaryEmulator Instance, ulong ThreadHandle)
        {
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
                return Instance.CurrentThread;

            EmulatedThread WinThreadObj = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
            if (WinThreadObj == null)
                return null;

            return WinThreadObj;
        }
    }
}