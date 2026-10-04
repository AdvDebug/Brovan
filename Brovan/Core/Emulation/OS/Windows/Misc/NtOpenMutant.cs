using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenMutant : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong MutantHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            return HandleOpenMutant(Instance, MutantHandlePtr, DesiredAccess, ObjectAttributesPtr);
        }

        private static NTSTATUS HandleOpenMutant(BinaryEmulator Instance, ulong MutantHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr)
        {
            if (MutantHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(MutantHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            uint Attributes = Instance.WinHelper.ReadObjectAttributesFlags(ObjectAttributesPtr);
            if (!Instance.WinHelper.TryLookupNameForOpen(FullName, Attributes, out WinMutex? Mutex, out NTSTATUS Status))
                return Status;

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Mutex, (AccessMask)(uint)DesiredAccess);

            if (!Instance.WinHelper.WritePointer(MutantHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
