using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryFullAttributesFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance) => NtQueryAttributesFile.Query(Instance, NetworkOpen: true);
    }
}
