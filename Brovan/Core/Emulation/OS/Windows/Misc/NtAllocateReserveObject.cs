using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateReserveObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ReserveHandlePtr = Instance.WinHelper.GetArg(0);
            uint Type = (uint)Instance.WinHelper.GetArg(2);

            if (!Instance.IsRegionMapped(ReserveHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Type > (uint)ReserveType.IoCompletion)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinReserveObject Reserve = new WinReserveObject
            {
                Name = Instance.WinHelper.GenerateAnonymousObjectName(Type == (uint)ReserveType.IoCompletion ? "IoCompletionReserve_" : "UserApcReserve_"),
                Type = (ReserveType)Type,
            };

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Reserve, AccessMask.StandardRightsAll);
            if (!Instance.WinHelper.WritePointer(ReserveHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
