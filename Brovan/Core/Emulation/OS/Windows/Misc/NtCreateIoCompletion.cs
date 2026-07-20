using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateIoCompletion : IWinSyscall
    {

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong IoCompletionHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong Count = Instance.WinHelper.GetArg(3);

                if (IoCompletionHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(IoCompletionHandlePtr, (uint)Instance.WinHelper.PointerSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint Id = Instance.WinHelper.GenerateRandomPID();
                WinIoCompletion IoCompletion = new WinIoCompletion
                {
                    Name = "IoCompletion_" + Id.ToString(),
                    Count = (uint)Count
                };

                WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(IoCompletion, (AccessMask)DesiredAccess);
                Instance.WinHelper.AddWinHandle(Handle);

                if (!Instance.WinHelper.WritePointer(IoCompletionHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            uint IoCompletionHandlePtr32 = (uint)Instance.WinHelper.GetArg(0);
            uint DesiredAccess32 = (uint)Instance.WinHelper.GetArg(1);
            uint Count32 = (uint)Instance.WinHelper.GetArg(3);

            if (IoCompletionHandlePtr32 == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoCompletionHandlePtr32, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Id32 = Instance.WinHelper.GenerateRandomPID();
            WinIoCompletion IoCompletion32 = new WinIoCompletion
            {
                Name = "IoCompletion_" + Id32.ToString(),
                Count = Count32
            };

            WinHandle Handle32 = Instance.WinHelper.HandleManager.AddHandle(IoCompletion32, (AccessMask)DesiredAccess32);
            Instance.WinHelper.AddWinHandle(Handle32);

            if (!Instance._emulator.WriteMemory(IoCompletionHandlePtr32, (uint)Handle32.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
