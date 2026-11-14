using System;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIWaitForVerticalBlankEvent : IWinSyscall
    {
        // D3DKMT_WAITFORVERTICALBLANKEVENT, the same on x86 and x64.
        private const int ArgumentsSize = 12;
        private const int OffsetDevice = 4;
        private const int OffsetSource = 8;

        // NT gives up on the vertical blank after 80 ms (DxgkWaitForVerticalBlankEvent).
        private const long TimeoutMilliseconds = 80;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            if (Thread.WaitActive)
                return Instance.WinHelper.ContinueParked(Thread);

            Span<byte> Arguments = stackalloc byte[ArgumentsSize];
            if (!Instance.ReadMemory(Instance.WinHelper.GetArg(0), Arguments))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            uint DeviceHandle = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetDevice));
            if (!Process.TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Arguments), out DxgkAdapter Adapter)
                || BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(OffsetSource)) >= Adapter.SourceCount
                || DeviceHandle != 0 && (!Process.TryGet(DeviceHandle, out DxgkDevice Device) || Device.Adapter != Adapter))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Instance.WinHelper.PendingConnectReplies.Count != 0)
                AlpcMessaging.DeliverConnectReplies(Instance, Thread.ThreadId);

            long Deadline = Math.Min(Instance.WinHelper.GetNextVerticalBlankTick(), Instance.CreateEmulatedDeadlineMilliseconds(TimeoutMilliseconds));
            return Instance.WinHelper.ParkUntil(Thread, Deadline, Alertable: false);
        }
    }
}
