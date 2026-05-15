using System;
using System.Runtime.InteropServices;
using System.Text;
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
            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint ThreadHandle = Instance.ReadMemoryUInt(SP + 4);
            int ThreadInformationClassValue = (int)Instance.ReadMemoryUInt(SP + 8);
            uint ThreadInformationPtr = Instance.ReadMemoryUInt(SP + 12);
            uint ThreadInformationLength = Instance.ReadMemoryUInt(SP + 16);

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

                        int Priority = (int)Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        Thread.BasePriority = ClampPriority(8 + Priority);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadAffinityMask:
                    {
                        uint PointerSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8u : 4u;

                        if (ThreadInformationPtr == 0 || ThreadInformationLength < PointerSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, PointerSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        ulong AffinityMask = PointerSize == 8
                            ? Instance.ReadMemoryULong(ThreadInformationPtr)
                            : Instance.ReadMemoryUInt(ThreadInformationPtr);

                        if (AffinityMask == 0)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        Thread.AffinityMask = AffinityMask;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadBasePriority:
                    {
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < 4)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        int BasePriority = (int)Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);
                        Thread.BasePriority = ClampPriority(BasePriority);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case THREADINFOCLASS.ThreadHideFromDebugger:
                    {
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
                        uint UsSize = (uint)Marshal.SizeOf<UNICODE_STRING64>();
                        if (ThreadInformationPtr == 0 || ThreadInformationLength < UsSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, UsSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (!StructSerializer.ParseStruct(Instance, ThreadInformationPtr, out UNICODE_STRING64 Us))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        string Name = ReadUnicodeString(Instance, Us);
                        Thread.Name = Name ?? string.Empty;
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                case THREADINFOCLASS.ThreadImpersonationToken:
                    {
                        int HandleSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8 : 4;

                        if (ThreadInformationPtr == 0 || ThreadInformationLength < (uint)HandleSize)
                            return NTSTATUS.STATUS_INVALID_PARAMETER;

                        if (!Instance.IsRegionMapped(ThreadInformationPtr, (uint)HandleSize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        ulong TokenHandleValue = HandleSize == 8
                            ? Instance._emulator.ReadMemoryULong(ThreadInformationPtr)
                            : Instance._emulator.ReadMemoryUInt(ThreadInformationPtr);

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
            uint PointerSize = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8u : 4u;

            if (ThreadInformationPtr == 0 || ThreadInformationLength < PointerSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ThreadInformationPtr, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong TlsArrayAddress = PointerSize == 8
                ? Instance.ReadMemoryULong(ThreadInformationPtr)
                : Instance.ReadMemoryUInt(ThreadInformationPtr);

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            ulong TlsPointerAddress = Teb + (PointerSize == 8 ? 0x58UL : 0x2CUL);

            if (!Instance.IsRegionMapped(TlsPointerAddress, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool Written = PointerSize == 8
                ? Instance._emulator.WriteMemory(TlsPointerAddress, TlsArrayAddress)
                : Instance._emulator.WriteMemory(TlsPointerAddress, (uint)TlsArrayAddress);

            return Written ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
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

        private static int ClampPriority(int Value)
        {
            if (Value < 1) return 1;
            if (Value > 31) return 31;
            return Value;
        }

        private static EmulatedThread ResolveThreadFromHandle(BinaryEmulator Instance, ulong ThreadHandle)
        {
            if (ThreadHandle == unchecked((ulong)0xFFFFFFFFFFFFFFFE) || ThreadHandle == 0xFFFFFFFEu)
                return Instance.CurrentThread;

            EmulatedThread WinThreadObj = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
            if (WinThreadObj == null)
                return null;

            return WinThreadObj;
        }

        private static string ReadUnicodeString(BinaryEmulator Instance, UNICODE_STRING64 UnicodeString)
        {
            if (UnicodeString.Length == 0 || UnicodeString.Buffer == 0)
                return string.Empty;

            if (!Instance.IsRegionMapped(UnicodeString.Buffer, UnicodeString.Length))
                return string.Empty;

            byte[] Data = Instance.ReadMemory(UnicodeString.Buffer, UnicodeString.Length);
            return Encoding.Unicode.GetString(Data).TrimEnd('\0');
        }
    }
}