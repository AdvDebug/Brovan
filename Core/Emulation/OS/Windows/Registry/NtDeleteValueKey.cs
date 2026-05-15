using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDeleteValueKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong KeyHandle = Instance.WinHelper.GetArg64(0);
                ulong ValueNamePtr = Instance.WinHelper.GetArg64(1);

                if (!Instance.WinHelper.TryReadUnicodeString64(ValueNamePtr, out string ValueName, out NTSTATUS Status))
                    return Status;

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                Instance.TriggerEventMessage($"[+] NtDeleteValueKey Running with the FullPath: {RegKey.FullPath}, ValueName: {ValueName}", LogFlags.Syscall);

                if (!Instance.WinHelper.DeleteRegistryValue(RegKey.FullPath, ValueName))
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}
