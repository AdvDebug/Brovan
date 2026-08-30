using System.IO.MemoryMappedFiles;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal enum SessionOperation : uint
    {
        None = 0,
        ReadMemory = 1,
        WriteMemory = 2,
        AllocateMemory = 3,
        CreateThread = 4,
        ResumeProcess = 5,
    }

    /// <summary>
    /// One request channel per session slot. A channel is idle when both sequence numbers match, so claiming it
    /// under the session lock is what keeps a single request in flight.
    /// </summary>
    internal static class GuestSessionMailbox
    {
        internal const int MaxPayloadBytes = ChannelSize - PayloadOffset;

        private const string FileName = "mailboxes.bin";
        private const int ChannelSize = 0x10000;

        private const int RequestSequenceOffset = 0x00;
        private const int ResponseSequenceOffset = 0x04;
        private const int OperationOffset = 0x08;
        private const int StatusOffset = 0x0C;
        private const int AddressOffset = 0x10;
        private const int ArgumentOffset = 0x18;
        private const int ResultOffset = 0x20;
        private const int LengthOffset = 0x28;
        private const int PayloadOffset = 0x40;

        private const int ResponseTimeoutMilliseconds = 5000;
        private const int ResponsePollMilliseconds = 1;

        private static FileStream _stream;
        private static MemoryMappedFile _map;
        private static MemoryMappedViewAccessor _view;
        private static uint _handledSequence;
        private static bool _unavailable;

        internal static NTSTATUS Send(
            int Slot,
            SessionOperation Operation,
            ulong Address,
            ulong Argument,
            ReadOnlySpan<byte> Input,
            Span<byte> Output,
            out int OutputLength,
            out ulong Result)
        {
            OutputLength = 0;
            Result = 0;

            if (Input.Length > MaxPayloadBytes || Output.Length > MaxPayloadBytes)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint Sequence;

            using (SessionLock Lock = GuestSession.Acquire())
            {
                if (!Lock.Held || !TryOpen())
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                long Base = ChannelOffset(Slot);
                Sequence = _view.ReadUInt32(Base + RequestSequenceOffset);
                if (Sequence != _view.ReadUInt32(Base + ResponseSequenceOffset))
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                _view.Write(Base + OperationOffset, (uint)Operation);
                _view.Write(Base + StatusOffset, 0u);
                _view.Write(Base + AddressOffset, Address);
                _view.Write(Base + ArgumentOffset, Argument);
                _view.Write(Base + ResultOffset, 0UL);
                _view.Write(Base + LengthOffset, (uint)(Operation == SessionOperation.ReadMemory ? Output.Length : Input.Length));

                if (Input.Length > 0)
                    WritePayload(Base, Input);

                Sequence++;
                _view.Write(Base + RequestSequenceOffset, Sequence);
                _view.Flush();
            }

            long Deadline = Environment.TickCount64 + ResponseTimeoutMilliseconds;

            while (Environment.TickCount64 < Deadline)
            {
                Thread.Sleep(ResponsePollMilliseconds);

                if (_view == null)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                using SessionLock Lock = GuestSession.Acquire();
                if (!Lock.Held)
                    continue;

                long Base = ChannelOffset(Slot);
                if (_view.ReadUInt32(Base + ResponseSequenceOffset) != Sequence)
                    continue;

                Result = _view.ReadUInt64(Base + ResultOffset);
                OutputLength = (int)Math.Min(_view.ReadUInt32(Base + LengthOffset), (uint)Output.Length);

                if (OutputLength > 0)
                    ReadPayload(Base, Output.Slice(0, OutputLength));

                return (NTSTATUS)_view.ReadUInt32(Base + StatusOffset);
            }

            return NTSTATUS.STATUS_TIMEOUT;
        }

        /// <summary>
        /// <paramref name="Length"/> is how many bytes the sender wants back for
        /// <see cref="SessionOperation.ReadMemory"/>, and how many it sent otherwise.
        /// </summary>
        internal static bool TryReceive(out SessionOperation Operation, out ulong Address, out ulong Argument, out int Length, out byte[] Input)
        {
            Operation = SessionOperation.None;
            Address = 0;
            Argument = 0;
            Length = 0;
            Input = null;

            int Slot = GuestSession.OwnSlot;

            if (Slot < 0 || _view == null)
                return false;

            long Base = ChannelOffset(Slot);

            // Peeked without the lock: the scheduler asks every slice, and the sender publishes the sequence last.
            if (_view.ReadUInt32(Base + RequestSequenceOffset) == _handledSequence)
                return false;

            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held)
                return false;

            uint Sequence = _view.ReadUInt32(Base + RequestSequenceOffset);
            if (Sequence == _handledSequence)
                return false;

            Operation = (SessionOperation)_view.ReadUInt32(Base + OperationOffset);
            Address = _view.ReadUInt64(Base + AddressOffset);
            Argument = _view.ReadUInt64(Base + ArgumentOffset);

            Length = (int)Math.Min(_view.ReadUInt32(Base + LengthOffset), (uint)MaxPayloadBytes);
            if (Length > 0 && Operation != SessionOperation.ReadMemory)
            {
                Input = new byte[Length];
                ReadPayload(Base, Input);
            }

            _handledSequence = Sequence;
            return true;
        }

        internal static void Complete(NTSTATUS Status, ulong Result, ReadOnlySpan<byte> Output)
        {
            int Slot = GuestSession.OwnSlot;
            if (Slot < 0 || _view == null)
                return;

            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held)
                return;

            long Base = ChannelOffset(Slot);
            int Length = Math.Min(Output.Length, MaxPayloadBytes);

            if (Length > 0)
                WritePayload(Base, Output.Slice(0, Length));

            _view.Write(Base + LengthOffset, (uint)Length);
            _view.Write(Base + ResultOffset, Result);
            _view.Write(Base + StatusOffset, (uint)Status);
            _view.Write(Base + ResponseSequenceOffset, _handledSequence);
            _view.Flush();
        }

        /// <summary>
        /// A reused slot still holds its previous owner's sequence numbers, which this process would run as a new
        /// request since it starts counting from zero.
        /// </summary>
        internal static void Reset(int Slot)
        {
            if (!TryOpen())
                return;

            long Base = ChannelOffset(Slot);
            for (int Offset = 0; Offset < PayloadOffset; Offset += 8)
                _view.Write(Base + Offset, 0UL);

            _view.Flush();
            _handledSequence = 0;
        }

        internal static void Close()
        {
            _view?.Dispose();
            _map?.Dispose();
            _stream?.Dispose();

            _view = null;
            _map = null;
            _stream = null;
        }

        private static bool TryOpen()
        {
            if (_view != null)
                return true;

            if (_unavailable)
                return false;

            try
            {
                System.IO.Directory.CreateDirectory(GuestSession.Directory);

                long Size = (long)GuestSession.SlotCount * ChannelSize;

                _stream = new FileStream(
                    Path.Combine(GuestSession.Directory, FileName),
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);

                if (_stream.Length < Size)
                    _stream.SetLength(Size);

                _map = MemoryMappedFile.CreateFromFile(_stream, null, Size, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                _view = _map.CreateViewAccessor(0, Size);
                return true;
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[GuestSessionMailbox] Unavailable: {Ex.Message}");
                _unavailable = true;
                _view = null;
                return false;
            }
        }

        private static void WritePayload(long Base, ReadOnlySpan<byte> Payload)
        {
            byte[] Buffer = Payload.ToArray();
            _view.WriteArray(Base + PayloadOffset, Buffer, 0, Buffer.Length);
        }

        private static void ReadPayload(long Base, Span<byte> Destination)
        {
            byte[] Buffer = new byte[Destination.Length];
            _view.ReadArray(Base + PayloadOffset, Buffer, 0, Buffer.Length);
            Buffer.CopyTo(Destination);
        }

        private static long ChannelOffset(int Slot) => (long)Slot * ChannelSize;
    }
}
