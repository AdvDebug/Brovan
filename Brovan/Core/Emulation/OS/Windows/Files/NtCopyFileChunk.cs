using System;
using System.Buffers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtCopyFileChunk : IWinSyscall
    {
        private const int CopyBufferBytes = 1 << 20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SourceHandle = Instance.WinHelper.GetArg(0);
            ulong DestinationHandle = Instance.WinHelper.GetArg(1);
            ulong EventHandle = Instance.WinHelper.GetArg(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(3);
            uint Length = (uint)Instance.WinHelper.GetArg(4);
            ulong SourceOffsetPtr = Instance.WinHelper.GetArg(5);
            ulong DestinationOffsetPtr = Instance.WinHelper.GetArg(6);

            NTSTATUS Status = Copy(Instance, SourceHandle, DestinationHandle, IoStatusBlockPtr, Length, SourceOffsetPtr, DestinationOffsetPtr);
            Instance.WinHelper.SignalIoEvent(EventHandle, Status);
            return Status;
        }

        private static NTSTATUS Copy(BinaryEmulator Instance, ulong SourceHandle, ulong DestinationHandle, ulong IoStatusBlockPtr, uint Length, ulong SourceOffsetPtr, ulong DestinationOffsetPtr)
        {
            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile Source = Instance.WinHelper.GetFileByHandle(SourceHandle, AccessMask.GiveTemp);
            WinFile Destination = Instance.WinHelper.GetFileByHandle(DestinationHandle, AccessMask.GiveTemp);

            if (Source == null || Destination == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (Source.Device || Destination.Device || Source.Pipe != null || Destination.Pipe != null
                || Source.Directory || Destination.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (!TryReadOffset(Instance, SourceOffsetPtr, Source.Position, out long SourceOffset)
                || !TryReadOffset(Instance, DestinationOffsetPtr, Destination.Position, out long DestinationOffset))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WindowsFileStream SourceStream = Source.GetFileStream();
            WindowsFileStream DestinationStream = Destination.GetFileStream(true);
            if (SourceStream == null || DestinationStream == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            int BufferSize = Length < CopyBufferBytes ? (int)Length : CopyBufferBytes;
            byte[] Buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            ulong Copied = 0;

            try
            {
                while (Copied < Length)
                {
                    int Wanted = (int)Math.Min((ulong)BufferSize, Length - Copied);
                    int Read = SourceStream.ReadAt(SourceOffset + (long)Copied, Buffer, 0, Wanted);
                    if (Read <= 0)
                        break;

                    DestinationStream.WriteAt(DestinationOffset + (long)Copied, Buffer, 0, Read);
                    Copied += (ulong)Read;

                    if (Read < Wanted)
                        break;
                }
            }
            catch
            {
                ArrayPool<byte>.Shared.Return(Buffer);
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            ArrayPool<byte>.Shared.Return(Buffer);
            Destination.Real = true;

            if (Copied == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                return NTSTATUS.STATUS_END_OF_FILE;
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Copied);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryReadOffset(BinaryEmulator Instance, ulong OffsetPtr, long Fallback, out long Offset)
        {
            Offset = Fallback;

            if (OffsetPtr == 0)
                return true;

            if (!Instance.IsRegionMapped(OffsetPtr, 8))
                return false;

            Offset = (long)Instance._emulator.ReadMemoryULong(OffsetPtr);
            return Offset >= 0;
        }
    }
}
