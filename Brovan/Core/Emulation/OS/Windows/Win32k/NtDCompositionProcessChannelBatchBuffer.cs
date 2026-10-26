using System;
using System.Buffers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionProcessChannelBatchBuffer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ChannelId = Instance.WinHelper.GetArg32(0);
            uint Bytes = Instance.WinHelper.GetArg32(1);
            ulong CountPtr = Instance.WinHelper.GetArg(2);
            ulong DeletedPtr = Instance.WinHelper.GetArg(3);

            uint Count = 0;
            NTSTATUS Status = Instance.WinHelper.Composition.Reference(ChannelId, out CompositionChannel Channel);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = Bytes > Channel.Size ? NTSTATUS.STATUS_INVALID_PARAMETER : Process(Instance, Channel, Bytes, ref Count);

            // NT writes both outputs whatever the status. No handled record sets a deletion tag, so the byte is 0.
            if (Instance.WinHelper.WriteUInt32(CountPtr, Count) && Instance.WinHelper.WriteByte(DeletedPtr, 0))
                return Status;

            return Status == NTSTATUS.STATUS_SUCCESS ? NTSTATUS.STATUS_ACCESS_VIOLATION : Status;
        }

        // Parse a copy, because other processors can write the page and the guest can unmap it meanwhile.
        private static unsafe NTSTATUS Process(BinaryEmulator Instance, CompositionChannel Channel, uint Bytes, ref uint Count)
        {
            byte[] Copy = ArrayPool<byte>.Shared.Rent((int)Bytes);
            try
            {
                new ReadOnlySpan<byte>((void*)Channel.Storage, (int)Bytes).CopyTo(Copy);
                return CompositionBatchParser.Process(Instance, Channel, Copy.AsSpan(0, (int)Bytes), ref Count);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Copy);
            }
        }
    }
}
