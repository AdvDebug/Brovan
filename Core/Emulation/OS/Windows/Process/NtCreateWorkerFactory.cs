using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateWorkerFactory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong WorkerFactoryHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
                ulong IoCompletionHandle = Instance.WinHelper.GetArg64(3);
                ulong WorkerProcessHandle = Instance.WinHelper.GetArg64(4);
                ulong StartRoutine = Instance.WinHelper.GetArg64(5);
                ulong StartParameter = Instance.WinHelper.GetArg64(6);
                uint MaxThreadCount = (uint)Instance.WinHelper.GetArg64(7);
                ulong StackReserve = Instance.WinHelper.GetArg64(8);
                ulong StackCommit = Instance.WinHelper.GetArg64(9);

                if (WorkerFactoryHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(WorkerFactoryHandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WinHelper.HandleExists(IoCompletionHandle, HandleType.IoCompletionHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (WorkerProcessHandle != ulong.MaxValue && !Instance.WinHelper.ValidProcessHandle(WorkerProcessHandle))
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
                Instance.WinHelper.WinHandles.Add(Handle);

                if (!Instance._emulator.WriteMemory(WorkerFactoryHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}