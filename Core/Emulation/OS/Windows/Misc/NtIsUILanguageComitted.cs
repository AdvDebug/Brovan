using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtIsUILanguageComitted : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.TriggerEventMessage("[+] NtIsUILanguageComitted: Treating install UI language as committed.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
