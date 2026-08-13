using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

                return Open(Instance, EventHandlePtr, DesiredAccess, ObjectAttributesPtr);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandlePtr = Instance.WinHelper.GetArg32(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg32(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg32(2);

                return Open(Instance, EventHandlePtr, DesiredAccess, ObjectAttributesPtr);
            }

            return Instance.WinUnimplemented;
        }

        private static NTSTATUS Open(BinaryEmulator Instance, ulong EventHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr)
        {
            if (EventHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(EventHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(FullName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            WinEvent Ev = Instance.WinHelper.HandleManager.GetObjectByObjectId<WinEvent>(FullName);
            if (Ev == null)
            {
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[!] NtOpenEvent: no event named \"{FullName}\".", LogFlags.Syscall);

                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Ev, (AccessMask)(uint)DesiredAccess);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WinHelper.WritePointer(EventHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
