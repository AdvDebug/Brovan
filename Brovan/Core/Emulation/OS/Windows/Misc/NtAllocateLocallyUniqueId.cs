using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateLocallyUniqueId : IWinSyscall
    {
        private static long _Next = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong LuidPtr = Instance.WinHelper.GetArg(0);
            if (LuidPtr == 0 || !Instance.IsRegionMapped(LuidPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Value = (ulong)Interlocked.Increment(ref _Next);
            Instance._emulator.WriteMemory(LuidPtr, Value, 8);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
