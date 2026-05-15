using System;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtRaiseException : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance == null || Instance._binary == null || Instance.WinHelper == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            ulong ExceptionRecordPtr = Instance.WinHelper.GetArg64(0);
            ulong ContextRecordPtr = Instance.WinHelper.GetArg64(1);

            bool FirstChance = Instance.WinHelper.GetArg64(2) != 0;
            _ = FirstChance;

            if (ExceptionRecordPtr == 0 || ContextRecordPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ExceptionRecordPtr, 0x98))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(ContextRecordPtr, 0x100))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint ContextFlags = (uint)Instance.ReadMemoryULong(ContextRecordPtr + 0x30);

            const uint CONTEXT_AMD64 = 0x00100000;
            const uint CONTEXT_CONTROL = 0x00000001;
            const uint CONTEXT_INTEGER = 0x00000002;

            if ((ContextFlags & CONTEXT_AMD64) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint ExceptionCode = Instance.ReadMemoryUInt(ExceptionRecordPtr + 0x00);
            uint NumberParameters = Instance.ReadMemoryUInt(ExceptionRecordPtr + 0x18);
            if (NumberParameters > 15)
                NumberParameters = 15;

            ulong[] Parameters = Array.Empty<ulong>();
            if (NumberParameters != 0)
            {
                Parameters = new ulong[NumberParameters];
                for (int i = 0; i < (int)NumberParameters; i++)
                {
                    Parameters[i] = Instance.ReadMemoryULong(ExceptionRecordPtr + 0x20UL + (ulong)(i * 8));
                }
            }

            if ((ContextFlags & CONTEXT_INTEGER) != 0)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Instance.ReadMemoryULong(ContextRecordPtr + 0x78));
                Instance.WriteRegister(Registers.UC_X86_REG_RCX, Instance.ReadMemoryULong(ContextRecordPtr + 0x80));
                Instance.WriteRegister(Registers.UC_X86_REG_RDX, Instance.ReadMemoryULong(ContextRecordPtr + 0x88));
                Instance.WriteRegister(Registers.UC_X86_REG_RBX, Instance.ReadMemoryULong(ContextRecordPtr + 0x90));

                Instance.WriteRegister(Registers.UC_X86_REG_RBP, Instance.ReadMemoryULong(ContextRecordPtr + 0xA0));
                Instance.WriteRegister(Registers.UC_X86_REG_RSI, Instance.ReadMemoryULong(ContextRecordPtr + 0xA8));
                Instance.WriteRegister(Registers.UC_X86_REG_RDI, Instance.ReadMemoryULong(ContextRecordPtr + 0xB0));

                Instance.WriteRegister(Registers.UC_X86_REG_R8, Instance.ReadMemoryULong(ContextRecordPtr + 0xB8));
                Instance.WriteRegister(Registers.UC_X86_REG_R9, Instance.ReadMemoryULong(ContextRecordPtr + 0xC0));
                Instance.WriteRegister(Registers.UC_X86_REG_R10, Instance.ReadMemoryULong(ContextRecordPtr + 0xC8));
                Instance.WriteRegister(Registers.UC_X86_REG_R11, Instance.ReadMemoryULong(ContextRecordPtr + 0xD0));
                Instance.WriteRegister(Registers.UC_X86_REG_R12, Instance.ReadMemoryULong(ContextRecordPtr + 0xD8));
                Instance.WriteRegister(Registers.UC_X86_REG_R13, Instance.ReadMemoryULong(ContextRecordPtr + 0xE0));
                Instance.WriteRegister(Registers.UC_X86_REG_R14, Instance.ReadMemoryULong(ContextRecordPtr + 0xE8));
                Instance.WriteRegister(Registers.UC_X86_REG_R15, Instance.ReadMemoryULong(ContextRecordPtr + 0xF0));
            }

            if ((ContextFlags & CONTEXT_CONTROL) != 0)
            {
                ulong Rsp = Instance.ReadMemoryULong(ContextRecordPtr + 0x98);
                ulong Rip = Instance.ReadMemoryULong(ContextRecordPtr + 0xF8);
                uint EFlags = (uint)Instance.ReadMemoryULong(ContextRecordPtr + 0x44);

                Instance.WriteRegister(Registers.UC_X86_REG_RSP, Rsp);
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Rip);
                Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, EFlags);
            }

            EmulatedThread CurrentThread = Instance.CurrentThread;
            if (CurrentThread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (WinEmulatedThread.GetState(CurrentThread).IsHandlingException)
            {
                WinEmulatedThread.GetState(CurrentThread).ExceptionNesting++;
                if (WinEmulatedThread.GetState(CurrentThread).ExceptionNesting > 2)
                {
                    Instance.WinHelper.AbandonMutexesOwnedByThread(CurrentThread.ThreadId);
                    CurrentThread.State = EmulatedThreadState.Terminated;
                    CurrentThread.ExitCode = unchecked((int)ExceptionCode);
                    Instance.Threads[(uint)Instance.CurrentThreadId] = CurrentThread;
                    Instance._emulator.StopEmulation();
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }
            else
            {
                WinEmulatedThread.GetState(CurrentThread).IsHandlingException = true;
                WinEmulatedThread.GetState(CurrentThread).ExceptionNesting = 1;
            }

            ExceptionInformation Info = new ExceptionInformation();
            Info.Status = (NTSTATUS)ExceptionCode;
            if (Parameters.Length != 0)
                Info.CustomParameters = Parameters;

            CurrentThread.State = EmulatedThreadState.Exception;
            WinEmulatedThread.GetState(CurrentThread).DispatchException = true;
            WinEmulatedThread.GetState(CurrentThread).ExceptionInformation = Info;
            CurrentThread.ExitCode = unchecked((int)ExceptionCode);

            Instance.Threads[(uint)Instance.CurrentThreadId] = CurrentThread;
            Instance.TriggerEventMessage($"[!] NtRaiseException triggered with Exception Code: 0x{ExceptionCode:X}", LogFlags.Issues);
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}