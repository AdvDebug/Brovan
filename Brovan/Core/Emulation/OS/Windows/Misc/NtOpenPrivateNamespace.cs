using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenPrivateNamespace : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong NamespaceHandlePtr = Instance.WinHelper.GetArg(0);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong BoundaryDescriptorPtr = Instance.WinHelper.GetArg(3);

            if (!Instance.IsMemoryRangeMapped(NamespaceHandlePtr, (ulong)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ReadObjectAttributes(ObjectAttributesPtr, out _, out _, out _, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = NtCreatePrivateNamespace.CaptureBoundary(Instance, BoundaryDescriptorPtr, out uint BoundarySize, out byte[][] BoundaryEntries);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            WinPrivateNamespace Namespace = Instance.WinHelper.FindPrivateNamespace(BoundarySize, BoundaryEntries);
            if (Namespace == null)
                return NTSTATUS.STATUS_OBJECT_PATH_NOT_FOUND;

            return NtCreatePrivateNamespace.InsertHandle(Instance, NamespaceHandlePtr, Namespace, DesiredAccess, Attributes);
        }
    }
}
