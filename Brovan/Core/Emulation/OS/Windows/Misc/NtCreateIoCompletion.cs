using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateIoCompletion : IWinSyscall
    {

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong IoCompletionHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask Permissions = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            uint Count = (uint)Instance.WinHelper.GetArg(3);

            if (IoCompletionHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoCompletionHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT ignores case for I/O completion names.
            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinIoCompletion? Existing, out Status, TypeIgnoresCase: true))
                return Status;

            WinIoCompletion? IoCompletion = Existing;
            if (IoCompletion == null)
            {
                IoCompletion = new WinIoCompletion
                {
                    Name = Name ?? Instance.WinHelper.GenerateAnonymousObjectName("IoCompletion_"),
                    Count = Count
                };

                if (Name != null)
                    Instance.WinHelper.AddNamedObject(IoCompletion);
            }

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(IoCompletion, Permissions);
            if (!Instance.WinHelper.WritePointer(IoCompletionHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }
    }
}
