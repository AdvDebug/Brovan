using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandlePtr = Instance.ReadRegister(Registers.UC_X86_REG_R10);
            ulong DesiredAccess = Instance.ReadRegister(Registers.UC_X86_REG_RDX);
            ulong ClientIdPtr = Instance.ReadRegister(Registers.UC_X86_REG_R9);

            if (ThreadHandlePtr == 0 || ClientIdPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Tid = Instance._emulator.ReadMemoryULong(ClientIdPtr + 0x8);
            EmulatedThread Thread = Instance.Threads.Values.FirstOrDefault(EmuThread => EmuThread.ThreadId == Tid);
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_CID;

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Thread, (AccessMask)DesiredAccess);
            Instance.WinHelper.WinHandles.Add(Handle);
            Instance._emulator.WriteMemory(ThreadHandlePtr, Handle.Handle, 8);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}