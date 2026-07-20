using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDeleteKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong KeyHandle = Instance.WinHelper.GetArg(0);

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtDeleteKey Running with the FullPath: {RegKey.FullPath}", LogFlags.Syscall);

                if (!Instance.WinHelper.DeleteRegistryKeyPath(RegKey.FullPath))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}
