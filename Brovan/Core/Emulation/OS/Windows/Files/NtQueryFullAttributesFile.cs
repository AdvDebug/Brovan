using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryFullAttributesFile : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) => NtQueryAttributesFile.ResolveQuery(Instance, NetworkOpen: true);

        public NTSTATUS Handle(BinaryEmulator Instance) => NtQueryAttributesFile.Query(Instance, NetworkOpen: true);
    }
}
