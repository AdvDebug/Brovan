using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong HandlePtr = Instance.WinHelper.GetArg64(0);
                AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

                if (HandlePtr == 0 || ObjectAttributesPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(HandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WinHelper.TryResolveRegistryObjectPath64(
                    ObjectAttributesPtr,
                    NTSTATUS.STATUS_ACCESS_VIOLATION,
                    NTSTATUS.STATUS_OBJECT_NAME_INVALID,
                    NTSTATUS.STATUS_INVALID_HANDLE,
                    out string KeyPath,
                    out NTSTATUS Status))
                {
                    return Status;
                }

                Instance.TriggerEventMessage($"[+] NtOpenKey Running with the KeyPath: {KeyPath}", LogFlags.Syscall);

                WinHandle Handle = Instance.WinHelper.OpenRegistryKey(KeyPath, DesiredAccess);
                if (Handle != null && Handle.Handle != 0)
                {
                    if (!Instance._emulator.WriteMemory(HandlePtr, Handle.Handle))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            return Instance.WinUnimplemented;
        }
    }
}
