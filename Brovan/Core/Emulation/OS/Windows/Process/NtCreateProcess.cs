using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateProcess : IWinSyscall
    {
        // NtCreateProcessEx without the trailing Reserved argument.
        public NTSTATUS Handle(BinaryEmulator Instance) => NtCreateProcessEx.Create(Instance, 0);
    }
}
