using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtFlushInstructionCache : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddress = Instance.WinHelper.GetArg(1);
            ulong Length = (uint)Instance.WinHelper.GetArg(2);

            if (!HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle) && !Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtFlushInstructionCache: base=0x{BaseAddress:X}, length=0x{Length:X}", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
