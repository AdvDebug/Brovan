using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtNotifyChangeKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong KeyHandle = Instance.WinHelper.GetArg64(0);
                ulong EventHandle = Instance.WinHelper.GetArg64(1);
                ulong ApcRoutine = Instance.WinHelper.GetArg64(2);
                ulong ApcContext = Instance.WinHelper.GetArg64(3);
                ulong IoStatusBlock = Instance.WinHelper.GetArg64(4);
                uint CompletionFilter = (uint)Instance.WinHelper.GetArg64(5, true);
                bool WatchTree = Instance.WinHelper.GetArg64(6, true) != 0;
                ulong Buffer = Instance.WinHelper.GetArg64(7);
                uint BufferSize = (uint)Instance.WinHelper.GetArg64(8, true);
                bool Asynchronous = Instance.WinHelper.GetArg64(9, true) != 0;

                WinRegKey RegKey = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRegKey>(KeyHandle);
                if (RegKey == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (EventHandle != 0 && Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.GiveTemp) == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (IoStatusBlock == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(IoStatusBlock, 0x10))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (BufferSize != 0)
                {
                    if (Buffer == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(Buffer, BufferSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (CompletionFilter == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Instance.TriggerEventMessage($"[+] NtNotifyChangeKey Running with the FullPath: {RegKey.FullPath}, Filter: 0x{CompletionFilter:X}, WatchTree: {WatchTree}, Async: {Asynchronous}", LogFlags.Syscall);

                if (!Asynchronous)
                {
                    Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, 0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlock, NTSTATUS.STATUS_PENDING, 0);
                Instance.WinHelper.RegisterRegistryNotification(new WinRegistryNotification
                {
                    KeyPath = RegKey.FullPath,
                    WatchTree = WatchTree,
                    CompletionFilter = CompletionFilter,
                    EventHandle = EventHandle,
                    KeyHandle = KeyHandle,
                    IoStatusBlock = IoStatusBlock,
                    ApcRoutine = ApcRoutine,
                    ApcContext = ApcContext,
                    Buffer = Buffer,
                    BufferSize = BufferSize,
                    ThreadId = Instance.CurrentThreadId
                });

                return NTSTATUS.STATUS_PENDING;
            }

            return Instance.WinUnimplemented;
        }
    }
}
