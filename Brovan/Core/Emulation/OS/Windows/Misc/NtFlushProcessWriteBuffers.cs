namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFlushProcessWriteBuffers : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // A processor drains its write buffer when it leaves the guest.
            Instance._emulator.HoldProcessorsOutOfGuest();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
