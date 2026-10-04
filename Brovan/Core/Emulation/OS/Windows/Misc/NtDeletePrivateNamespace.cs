using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtDeletePrivateNamespace : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong NamespaceHandle = Instance.WinHelper.GetArg(0);

            if (HandleManager.IsCurrentProcessPseudoHandle(NamespaceHandle) || HandleManager.IsCurrentThreadPseudoHandle(NamespaceHandle))
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            IHandleObject? Object = Instance.WinHelper.HandleManager.GetObjectByHandle(NamespaceHandle);
            if (Object == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (Object is not WinPrivateNamespace Namespace)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (!Instance.WinHelper.HandleManager.CheckAccess(NamespaceHandle, AccessMask.Delete))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (!Instance.WinHelper.PrivateNamespaces.Contains(Namespace))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            NTSTATUS Status = NtCreatePrivateNamespace.VerifyCreatorAccess(Instance);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Instance.WinHelper.PrivateNamespaces.Remove(Namespace);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
