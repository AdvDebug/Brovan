using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong JobHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask Permissions = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            if (JobHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(JobHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinJob? Existing, out Status))
                return Status;

            WinHandle Handle = Existing != null
                ? Instance.WinHelper.OpenObjectHandle(Existing, Permissions)
                : Instance.WinHelper.CreateJobHandle(Name, Permissions);

            if (!Instance.WinHelper.WritePointer(JobHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }
    }
}
