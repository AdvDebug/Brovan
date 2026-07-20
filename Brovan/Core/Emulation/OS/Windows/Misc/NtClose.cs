using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtClose : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong Handle = Instance.WinHelper.GetArg(0);

                if (HandleManager.IsCurrentProcessPseudoHandle(Handle) || HandleManager.IsCurrentThreadPseudoHandle(Handle))
                    return NTSTATUS.STATUS_SUCCESS;

                if (Instance.WinHelper.HandleExists(Handle))
                {
                    if ((Instance.WinHelper.HandleManager.GetHandleFlags(Handle) & ObjectHandleFlags.ProtectFromClose) != 0)
                        return NTSTATUS.STATUS_HANDLE_NOT_CLOSABLE;

                    Instance.WinHelper.CloseHandle(Handle);
                    return NTSTATUS.STATUS_SUCCESS;
                }
                else
                {
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] NtClose: received invalid handle 0x{Handle:X}.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_INVALID_HANDLE;
                }
            }
            else
            {
                uint Handle = Instance.WinHelper.GetArg32(0);

                if (HandleManager.IsCurrentProcessPseudoHandle(Handle) || HandleManager.IsCurrentThreadPseudoHandle(Handle))
                    return NTSTATUS.STATUS_SUCCESS;

                if (Instance.WinHelper.HandleExists(Handle))
                {
                    if ((Instance.WinHelper.HandleManager.GetHandleFlags(Handle) & ObjectHandleFlags.ProtectFromClose) != 0)
                        return NTSTATUS.STATUS_HANDLE_NOT_CLOSABLE;

                    Instance.WinHelper.CloseHandle(Handle);
                    return NTSTATUS.STATUS_SUCCESS;
                }
                else
                {
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] NtClose: received invalid handle 0x{Handle:X}.", LogFlags.Syscall);
                    return NTSTATUS.STATUS_INVALID_HANDLE;
                }
            }
        }
    }
}