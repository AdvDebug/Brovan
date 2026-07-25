using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnumDisplayMonitors : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong EnumProc = Instance.WinHelper.GetArg(2);
            ulong CallbackData = Instance.WinHelper.GetArg(3);

            ulong Monitor = Instance.WinHelper.GetPrimaryMonitorHandle();
            if (Monitor == 0 || !Instance.WinHelper.TryGetPrimaryMonitorRect(out int Left, out int Top, out int Right, out int Bottom))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (EnumProc == 0)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Rect = Instance.WinHelper.EnsureGuestCallScratch();
            if (Rect == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance._emulator.WriteMemory(Rect + 0x00, (uint)Left, 4);
            Instance._emulator.WriteMemory(Rect + 0x04, (uint)Top, 4);
            Instance._emulator.WriteMemory(Rect + 0x08, (uint)Right, 4);
            Instance._emulator.WriteMemory(Rect + 0x0C, (uint)Bottom, 4);

            if (!Instance.WinHelper.BeginGuestCall(EnumProc, Monitor, Hdc, Rect, CallbackData, 1))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
