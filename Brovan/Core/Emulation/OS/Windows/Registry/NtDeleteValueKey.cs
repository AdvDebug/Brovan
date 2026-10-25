using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDeleteValueKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong KeyHandle = Instance.WinHelper.GetArg(0);
            ulong ValueNamePtr = Instance.WinHelper.GetArg(1);

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(KeyHandle, AccessMask.KeySetValue, out WinRegKey RegKey);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryReadUnicodeString(ValueNamePtr, out string ValueName, out Status))
                return Status;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtDeleteValueKey Running with the FullPath: {RegKey.FullPath}, ValueName: {ValueName}", LogFlags.Syscall);

            if (!Instance.WinHelper.DeleteRegistryValue(RegKey.FullPath, ValueName))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
