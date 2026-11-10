using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateLocallyUniqueId : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong LuidPtr = Instance.WinHelper.GetArg(0);
            if (LuidPtr == 0 || !Instance.IsRegionMapped(LuidPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(LuidPtr, Allocate(), 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static ulong Allocate() => SessionIds.Next(SessionIdKind.Luid);
    }
}
