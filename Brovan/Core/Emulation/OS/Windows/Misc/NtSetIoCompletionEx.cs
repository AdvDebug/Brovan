using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetIoCompletionEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong IoCompletionHandle = Instance.WinHelper.GetArg(0);
            ulong ReserveHandle = Instance.WinHelper.GetArg(1);
            ulong KeyContext = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            NTSTATUS IoStatus = (NTSTATUS)(int)(uint)Instance.WinHelper.GetArg(4);
            ulong IoStatusInformation = Instance.WinHelper.GetArg(5);

            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(IoCompletionHandle, AccessMask.None, out WinIoCompletion Completion);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = Instance.WinHelper.ReferenceObjectByHandle(ReserveHandle, AccessMask.None, out WinReserveObject Reserve);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            // NT has one object type for each kind of reserve object.
            if (Reserve.Type != ReserveType.IoCompletion)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (Reserve.InUse)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            Reserve.InUse = true;
            Instance.WinHelper.PostCompletion(Instance, IoCompletionHandle, Completion, new WinIoCompletionEntry
            {
                KeyContext = KeyContext,
                ApcContext = ApcContext,
                IoStatus = IoStatus,
                IoStatusInformation = IoStatusInformation,
                Reserve = Reserve,
            });

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
