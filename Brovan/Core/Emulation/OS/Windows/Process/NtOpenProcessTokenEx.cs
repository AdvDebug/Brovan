using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtOpenProcessTokenEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NtOpenProcessToken.Open(Instance, 3);
        }
    }
}
