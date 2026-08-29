using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64AllocateVirtualMemory64 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg(4);
            uint AllocationType = (uint)Instance.WinHelper.GetArg(5);
            uint Protect = (uint)Instance.WinHelper.GetArg(6);

            // An x86 guest has no 64-bit half of its own to allocate in, only a view of another process.
            if (HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            return NtAllocateVirtualMemory.AllocateRemote(Instance, ProcessHandle, BaseAddressPtr, RegionSizePtr, AllocationType, Protect, 8);
        }
    }
}
