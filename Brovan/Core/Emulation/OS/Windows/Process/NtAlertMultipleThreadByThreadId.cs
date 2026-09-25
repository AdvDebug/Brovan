using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlertMultipleThreadByThreadId : IWinSyscall
    {
        private const uint ChunkIds = 256;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadIds = Instance.WinHelper.GetArg(0);
            uint Count = (uint)Instance.WinHelper.GetArg(1);
            _ = Instance.WinHelper.GetArg(2);
            _ = Instance.WinHelper.GetArg(3);

            if (Count == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (ThreadIds == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // The ids are HANDLE-sized.
            uint IdSize = (uint)Instance.WinHelper.PointerSize;
            Span<byte> Chunk = stackalloc byte[(int)(ChunkIds * 8)];

            NTSTATUS FirstFailure = NTSTATUS.STATUS_SUCCESS;
            for (uint Done = 0; Done < Count;)
            {
                uint Batch = Math.Min(ChunkIds, Count - Done);
                Span<byte> Ids = Chunk.Slice(0, (int)(Batch * IdSize));
                if (!Instance._emulator.ReadMemory(ThreadIds + (ulong)Done * IdSize, Ids))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                for (uint Index = 0; Index < Batch; Index++)
                {
                    uint ThreadId = IdSize == 8
                        ? (uint)BinaryPrimitives.ReadUInt64LittleEndian(Ids.Slice((int)(Index * 8), 8))
                        : BinaryPrimitives.ReadUInt32LittleEndian(Ids.Slice((int)(Index * 4), 4));

                    NTSTATUS Status = NtAlertThreadByThreadId.AlertThread(Instance, ThreadId);
                    if (Status != NTSTATUS.STATUS_SUCCESS && FirstFailure == NTSTATUS.STATUS_SUCCESS)
                        FirstFailure = Status;
                }

                Done += Batch;
            }

            return FirstFailure;
        }
    }
}
