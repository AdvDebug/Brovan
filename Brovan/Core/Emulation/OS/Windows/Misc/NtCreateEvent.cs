using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong EventHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributes = Instance.WinHelper.GetArg(2);
            uint EventType = (uint)Instance.WinHelper.GetArg(3);
            bool InitialState = (byte)Instance.WinHelper.GetArg(4) != 0;

            if (EventHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(EventHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (EventType > 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributes, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinEvent? Existing, out Status))
                return Status;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Existing != null
                ? Instance.WinHelper.OpenObjectHandle(Existing, Permissions)
                : Instance.WinHelper.CreateEventHandle(Name, EventType, InitialState, Permissions);

            if (!Instance.WinHelper.WritePointer(EventHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }
    }
}
