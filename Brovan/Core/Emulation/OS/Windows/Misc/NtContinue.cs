using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtContinue : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ContextPtr = Instance.WinHelper.GetArg64(0);
            bool TestAlert = (uint)Instance.WinHelper.GetArg64(1) != 0;

            return Continue(Instance, ContextPtr, TestAlert);
        }

        internal static NTSTATUS Continue(BinaryEmulator Instance, ulong ContextPtr, bool TestAlert)
        {
            if (ContextPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(ContextPtr, 0x200))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Flags = (uint)Instance.ReadMemoryULong(ContextPtr + 0x30);

            const uint CONTEXT_AMD64 = 0x00100000;
            const uint CONTEXT_CONTROL = 0x00000001;
            const uint CONTEXT_INTEGER = 0x00000002;

            if ((Flags & CONTEXT_AMD64) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Instance.ReadMemoryULong(ContextPtr + 0x78));
                Instance.WriteRegister(Registers.UC_X86_REG_RCX, Instance.ReadMemoryULong(ContextPtr + 0x80));
                Instance.WriteRegister(Registers.UC_X86_REG_RDX, Instance.ReadMemoryULong(ContextPtr + 0x88));
                Instance.WriteRegister(Registers.UC_X86_REG_RBX, Instance.ReadMemoryULong(ContextPtr + 0x90));

                Instance.WriteRegister(Registers.UC_X86_REG_RBP, Instance.ReadMemoryULong(ContextPtr + 0xA0));
                Instance.WriteRegister(Registers.UC_X86_REG_RSI, Instance.ReadMemoryULong(ContextPtr + 0xA8));
                Instance.WriteRegister(Registers.UC_X86_REG_RDI, Instance.ReadMemoryULong(ContextPtr + 0xB0));

                Instance.WriteRegister(Registers.UC_X86_REG_R8, Instance.ReadMemoryULong(ContextPtr + 0xB8));
                Instance.WriteRegister(Registers.UC_X86_REG_R9, Instance.ReadMemoryULong(ContextPtr + 0xC0));
                Instance.WriteRegister(Registers.UC_X86_REG_R10, Instance.ReadMemoryULong(ContextPtr + 0xC8));
                Instance.WriteRegister(Registers.UC_X86_REG_R11, Instance.ReadMemoryULong(ContextPtr + 0xD0));
                Instance.WriteRegister(Registers.UC_X86_REG_R12, Instance.ReadMemoryULong(ContextPtr + 0xD8));
                Instance.WriteRegister(Registers.UC_X86_REG_R13, Instance.ReadMemoryULong(ContextPtr + 0xE0));
                Instance.WriteRegister(Registers.UC_X86_REG_R14, Instance.ReadMemoryULong(ContextPtr + 0xE8));
                Instance.WriteRegister(Registers.UC_X86_REG_R15, Instance.ReadMemoryULong(ContextPtr + 0xF0));
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                ulong Rsp = Instance.ReadMemoryULong(ContextPtr + 0x98);
                ulong Rip = Instance.ReadMemoryULong(ContextPtr + 0xF8);
                uint EFlags = (uint)Instance.ReadMemoryULong(ContextPtr + 0x44);
                Instance.WriteRegister(Registers.UC_X86_REG_RSP, Rsp);
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Rip);
                Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, EFlags);
            }

            EmulatedThread CurrentThread = Instance.CurrentThread;
            if (CurrentThread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(CurrentThread);
            State.DispatchException = false;
            State.IsHandlingException = false;
            State.ExceptionNesting = 0;
            State.ExceptionInformation = null;

            if (CurrentThread.State == EmulatedThreadState.Exception)
                CurrentThread.State = EmulatedThreadState.Running;

            if (TestAlert)
                Instance.WinHelper.DispatchNextUserApc(CurrentThread, true);

            CurrentThread.SwitchContext(Instance);
            CurrentThread.SwitchingContext = true;
            Instance.SuppressSyscallStatusWrite = true;

            // NtContinue resumes the current thread with the supplied context. It is also the
            // normal return path from KiUserExceptionDispatcher after a continuable exception.
            // Stopping the whole emulator here incorrectly terminates all threads before the
            // restored user context can run.
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
