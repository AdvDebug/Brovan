using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetPointerInfoList : IWinSyscall
    {
        private const int PointerInfoSize = 0x60;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint PointerId = (uint)Instance.WinHelper.GetArg(0);
            uint EntrySize = (uint)Instance.WinHelper.GetArg(4);
            ulong EntryCountPtr = Instance.WinHelper.GetArg(5);
            ulong PointerCountPtr = Instance.WinHelper.GetArg(6);
            ulong BufferPtr = Instance.WinHelper.GetArg(7);

            if (EntrySize < PointerInfoSize || BufferPtr == 0 || !Instance.IsRegionMapped(BufferPtr, EntrySize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(EntrySize).Slice(0, (int)EntrySize);
            Buffer.Clear();

            if (!Win32kHelper.TryWritePointerInfo(Instance, PointerId, Buffer))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WriteMemory(BufferPtr, Buffer))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // The pointer history is the current state only.
            if (EntryCountPtr != 0 && Instance.IsRegionMapped(EntryCountPtr, 4))
                Instance._emulator.WriteMemory(EntryCountPtr, 1u, 4);

            if (PointerCountPtr != 0 && Instance.IsRegionMapped(PointerCountPtr, 4))
                Instance._emulator.WriteMemory(PointerCountPtr, 1u, 4);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
