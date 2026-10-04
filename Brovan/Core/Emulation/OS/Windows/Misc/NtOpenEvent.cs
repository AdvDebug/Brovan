using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong EventHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            return Open(Instance, EventHandlePtr, DesiredAccess, ObjectAttributesPtr);
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

            uint Attributes = Instance.WinHelper.ReadObjectAttributesFlags(ObjectAttributesPtr);
            if (!Instance.WinHelper.TryLookupNameForOpen(FullName, Attributes, out WinEvent? Ev, out NTSTATUS Status))
            {
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[!] NtOpenEvent: no event named \"{FullName}\".", LogFlags.Syscall);

                return Status;
            }

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Ev, (AccessMask)(uint)DesiredAccess);

            if (!Instance.WinHelper.WritePointer(EventHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
