using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateWorkerFactory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong WorkerFactoryHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
                ulong IoCompletionHandle = Instance.WinHelper.GetArg(3);
                ulong WorkerProcessHandle = Instance.WinHelper.GetArg(4);
                ulong StartRoutine = Instance.WinHelper.GetArg(5);
                ulong StartParameter = Instance.WinHelper.GetArg(6);
                uint MaxThreadCount = (uint)Instance.WinHelper.GetArg(7);
                ulong StackReserve = Instance.WinHelper.GetArg(8);
                ulong StackCommit = Instance.WinHelper.GetArg(9);

                if (WorkerFactoryHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(WorkerFactoryHandlePtr, (uint)Instance.WinHelper.PointerSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WinHelper.HandleExists(IoCompletionHandle, HandleType.IoCompletionHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (!HandleManager.IsCurrentProcessPseudoHandle(WorkerProcessHandle) && !Instance.WinHelper.ValidProcessHandle(WorkerProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                uint Id = Instance.WinHelper.GenerateRandomPID();
                WinWorkerFactory Factory = new WinWorkerFactory
                {
                    Name = "WorkerFactory_" + Id.ToString(),
                    FactoryId = Id,
                    IoCompletionHandle = IoCompletionHandle,
                    WorkerProcessHandle = WorkerProcessHandle,
                    StartRoutine = StartRoutine,
                    StartParameter = StartParameter,
                    MaxThreadCount = MaxThreadCount,
                    StackReserve = StackReserve,
                    StackCommit = StackCommit,
                    ThreadMaximum = MaxThreadCount
                };

                WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Factory, (AccessMask)DesiredAccess);
                Instance.WinHelper.AddWinHandle(Handle);

                if (!Instance.WinHelper.WritePointer(WorkerFactoryHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}