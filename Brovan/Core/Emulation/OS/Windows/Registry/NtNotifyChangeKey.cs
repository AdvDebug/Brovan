using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtNotifyChangeKey : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong KeyHandle = Instance.WinHelper.GetArg(0);
                ulong EventHandle = Instance.WinHelper.GetArg(1);
                ulong ApcRoutine = Instance.WinHelper.GetArg(2);
                ulong ApcContext = Instance.WinHelper.GetArg(3);
                ulong IoStatusBlock = Instance.WinHelper.GetArg(4);
                uint CompletionFilter = (uint)Instance.WinHelper.GetArg(5);
                bool WatchTree = Instance.WinHelper.GetArg(6) != 0;
                ulong Buffer = Instance.WinHelper.GetArg(7);
                uint BufferSize = (uint)Instance.WinHelper.GetArg(8);
                bool Asynchronous = Instance.WinHelper.GetArg(9) != 0;

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

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtNotifyChangeKey Running with the FullPath: {RegKey.FullPath}, Filter: 0x{CompletionFilter:X}, WatchTree: {WatchTree}, Async: {Asynchronous}", LogFlags.Syscall);

                if (!Asynchronous)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_SUCCESS, 0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlock, NTSTATUS.STATUS_PENDING, 0);
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
