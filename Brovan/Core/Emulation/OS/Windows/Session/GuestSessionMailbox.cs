using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using Brovan.Core.Helpers;

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
        QueryMemory = 6,
        FreeMemory = 7,
        ProtectMemory = 8,
    }

    /// <summary>
    /// Requests to other guest processes of the session. Each process has one lane into every other process.
    /// Senders without a session slot share the last lane.
    /// </summary>
    internal static class GuestSessionMailbox
    {
        internal const int MaxPayloadBytes = LaneSize - LaneHeaderSize;

        private const string FileName = "mailboxes.bin";

        private const int LaneCount = GuestSession.SlotCount + 1;
        private const int SharedLane = GuestSession.SlotCount;
        private const int LaneSize = 0x10000;

        private const int DoorbellOffset = 0x00;
        private const int TargetHeaderSize = 0x40;
        private const int TargetSize = TargetHeaderSize + LaneCount * LaneSize;

        private const int RequestSequenceOffset = 0x00;
        private const int AnswerSequenceOffset = 0x04;
        private const int ReleasedSequenceOffset = 0x08;
        private const int OperationOffset = 0x0C;
        private const int AddressOffset = 0x10;
        private const int ArgumentOffset = 0x18;
        private const int LengthOffset = 0x20;
        private const int StatusOffset = 0x24;
        private const int ResultOffset = 0x28;
        private const int AnswerLengthOffset = 0x30;
        private const int AnswerTickOffset = 0x38;
        private const int LaneHeaderSize = 0x40;

        private const int ResponseTimeoutMilliseconds = 5000;
        private const int ResponsePollMilliseconds = 1;

        // Answers often arrive well within one poll interval, so the sender spins first.
        private static readonly long ResponseSpinTicks = Stopwatch.Frequency / 5000;

        private static FileStream _stream;
        private static MemoryMappedFile _map;
        private static MemoryMappedViewAccessor _view;
        private static unsafe byte* _viewBase;
        private static bool _unavailable;

        private static readonly uint[] _handledSequences = new uint[LaneCount];
        private static uint _seenDoorbell;
        private static bool _rescan;
        private static int _nextLane;
        private static int _activeLane = -1;

        private enum Claim
        {
            Claimed,
            Busy,
            Unavailable,
        }

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

            long Target = TargetOffset(Slot);
            long Lane = LaneOffset(Target, GuestSession.OwnSlot);
            long Deadline = Environment.TickCount64 + ResponseTimeoutMilliseconds;
            Backoff Wait = Backoff.Start();
            uint Sequence;

            while (true)
            {
                Claim Claimed = TryClaim(Target, Lane, Operation, Address, Argument, Input, Output.Length, out Sequence);
                if (Claimed == Claim.Unavailable)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;
                if (Claimed == Claim.Claimed)
                    break;

                // STATUS_TIMEOUT is a success code.
                if (Environment.TickCount64 >= Deadline)
                    return NTSTATUS.STATUS_IO_TIMEOUT;
                Wait.Pause();
            }

            Wait = Backoff.Start();
            while (true)
            {
                if (_view == null)
                    return NTSTATUS.STATUS_NOT_SUPPORTED;

                if (Peek(Lane + AnswerSequenceOffset) == Sequence)
                {
                    using SessionLock Lock = GuestSession.Acquire();
                    if (Lock.Held)
                    {
                        // Another sender took over the shared lane after this answer sat unread for a full timeout.
                        if (_view.ReadUInt32(Lane + RequestSequenceOffset) != Sequence)
                            return NTSTATUS.STATUS_IO_TIMEOUT;

                        Result = _view.ReadUInt64(Lane + ResultOffset);
                        OutputLength = (int)Math.Min(_view.ReadUInt32(Lane + AnswerLengthOffset), (uint)Output.Length);

                        if (OutputLength > 0)
                            PayloadSpan(Lane).Slice(0, OutputLength).CopyTo(Output);

                        NTSTATUS Status = (NTSTATUS)_view.ReadUInt32(Lane + StatusOffset);
                        _view.Write(Lane + ReleasedSequenceOffset, Sequence);
                        return Status;
                    }
                }

                if (Environment.TickCount64 >= Deadline)
                {
                    Release(Lane, Sequence);
                    return NTSTATUS.STATUS_IO_TIMEOUT;
                }
                Wait.Pause();
            }
        }

        private static Claim TryClaim(long Target, long Lane, SessionOperation Operation, ulong Address, ulong Argument, ReadOnlySpan<byte> Input,
            int OutputLength, out uint Sequence)
        {
            Sequence = 0;
            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held || !TryOpen())
                return Claim.Unavailable;

            uint Last = _view.ReadUInt32(Lane + RequestSequenceOffset);
            if (!IsLaneFree(Lane, Last))
                return Claim.Busy;

            _view.Write(Lane + OperationOffset, (uint)Operation);
            _view.Write(Lane + AddressOffset, Address);
            _view.Write(Lane + ArgumentOffset, Argument);
            _view.Write(Lane + LengthOffset, (uint)(Operation == SessionOperation.ReadMemory ? OutputLength : Input.Length));

            if (Input.Length > 0)
                Input.CopyTo(PayloadSpan(Lane));

            Sequence = Last + 1;
            _view.Write(Lane + RequestSequenceOffset, Sequence);
            _view.Write(Target + DoorbellOffset, _view.ReadUInt32(Target + DoorbellOffset) + 1);
            return Claim.Claimed;
        }

        // An answer nobody read for a whole timeout belongs to a sender that is gone.
        private static bool IsLaneFree(long Lane, uint Last)
            => _view.ReadUInt32(Lane + AnswerSequenceOffset) == Last
                && (_view.ReadUInt32(Lane + ReleasedSequenceOffset) == Last
                    || Environment.TickCount64 - _view.ReadInt64(Lane + AnswerTickOffset) >= ResponseTimeoutMilliseconds);

        private static void Release(long Lane, uint Sequence)
        {
            using SessionLock Lock = GuestSession.Acquire();
            if (Lock.Held && _view != null && _view.ReadUInt32(Lane + RequestSequenceOffset) == Sequence)
                _view.Write(Lane + ReleasedSequenceOffset, Sequence);
        }

        /// <summary>
        /// <paramref name="Length"/> is how many bytes the sender wants back for
        /// <see cref="SessionOperation.ReadMemory"/>, and how many it sent otherwise.
        /// </summary>
        /// <param name="Payload">The lane's payload area. It holds the request, and the answer is written over it.</param>
        internal static bool TryReceive(out SessionOperation Operation, out ulong Address, out ulong Argument, out int Length, out Span<byte> Payload)
        {
            Operation = SessionOperation.None;
            Address = 0;
            Argument = 0;
            Length = 0;
            Payload = Span<byte>.Empty;

            int Slot = GuestSession.OwnSlot;
            if (Slot < 0 || _view == null)
                return false;

            // Peeked without the lock because the scheduler calls this every slice.
            long Target = TargetOffset(Slot);
            if (!_rescan && Peek(Target + DoorbellOffset) == _seenDoorbell)
                return false;

            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held)
                return false;

            _seenDoorbell = _view.ReadUInt32(Target + DoorbellOffset);
            for (int i = 0; i < LaneCount; i++)
            {
                int Index = (_nextLane + i) % LaneCount;
                long Lane = LaneOffset(Target, Index);
                uint Sequence = _view.ReadUInt32(Lane + RequestSequenceOffset);
                if (Sequence == _handledSequences[Index])
                    continue;

                Operation = (SessionOperation)_view.ReadUInt32(Lane + OperationOffset);
                Address = _view.ReadUInt64(Lane + AddressOffset);
                Argument = _view.ReadUInt64(Lane + ArgumentOffset);
                Length = (int)Math.Min(_view.ReadUInt32(Lane + LengthOffset), (uint)MaxPayloadBytes);
                Payload = PayloadSpan(Lane);

                _handledSequences[Index] = Sequence;
                _activeLane = Index;
                _nextLane = (Index + 1) % LaneCount;
                _rescan = true;
                return true;
            }

            _rescan = false;
            return false;
        }

        internal static void Complete(NTSTATUS Status, ulong Result, int Length)
        {
            int Slot = GuestSession.OwnSlot;
            if (Slot < 0 || _view == null || _activeLane < 0)
                return;

            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held)
                return;

            long Lane = LaneOffset(TargetOffset(Slot), _activeLane);
            _view.Write(Lane + AnswerLengthOffset, (uint)Math.Min(Length, MaxPayloadBytes));
            _view.Write(Lane + ResultOffset, Result);
            _view.Write(Lane + StatusOffset, (uint)Status);
            _view.Write(Lane + AnswerTickOffset, Environment.TickCount64);
            _view.Write(Lane + AnswerSequenceOffset, _handledSequences[_activeLane]);
            _activeLane = -1;
        }

        /// <summary>
        /// A reused slot keeps its previous owner's sequence numbers and unread answers. The caller holds the session lock.
        /// </summary>
        internal static unsafe void Reset(int Slot)
        {
            if (!TryOpen())
                return;

            long Target = TargetOffset(Slot);
            new Span<byte>(_viewBase + Target, TargetHeaderSize).Clear();
            for (int Index = 0; Index < LaneCount; Index++)
                new Span<byte>(_viewBase + LaneOffset(Target, Index), LaneHeaderSize).Clear();

            for (int Other = 0; Other < GuestSession.SlotCount; Other++)
            {
                if (Other == Slot)
                    continue;

                long Lane = LaneOffset(TargetOffset(Other), Slot);
                _view.Write(Lane + ReleasedSequenceOffset, _view.ReadUInt32(Lane + RequestSequenceOffset));
            }

            Array.Clear(_handledSequences);
            _seenDoorbell = 0;
            _rescan = false;
            _nextLane = 0;
            _activeLane = -1;
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

        private static unsafe bool TryOpen()
        {
            if (_view != null)
                return true;

            if (_unavailable)
                return false;

            try
            {
                System.IO.Directory.CreateDirectory(GuestSession.Directory);

                long Size = (long)GuestSession.SlotCount * TargetSize;

                _stream = new FileStream(
                    Path.Combine(GuestSession.Directory, FileName),
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete);

                if (_stream.Length < Size)
                    _stream.SetLength(Size);

                _map = MemoryMappedFile.CreateFromFile(_stream, null, Size, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true);
                _view = _map.CreateViewAccessor(0, Size);

                byte* Pointer = null;
                _view.SafeMemoryMappedViewHandle.AcquirePointer(ref Pointer);
                _viewBase = Pointer + _view.PointerOffset;
                return true;
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[GuestSessionMailbox] Unavailable: {Ex.Message}");
                _unavailable = true;
                _view = null;
                _viewBase = null;
                return false;
            }
        }

        private static unsafe uint Peek(long Offset) => Volatile.Read(ref *(uint*)(_viewBase + Offset));

        private static unsafe Span<byte> PayloadSpan(long Lane) => new(_viewBase + Lane + LaneHeaderSize, MaxPayloadBytes);

        private static long TargetOffset(int Slot) => (long)Slot * TargetSize;

        private static long LaneOffset(long Target, int Sender)
            => Target + TargetHeaderSize + (long)(Sender >= 0 ? Sender : SharedLane) * LaneSize;

        private struct Backoff
        {
            private long _spinEnd;
            private SpinWait _spinner;

            public static Backoff Start() => new() { _spinEnd = Stopwatch.GetTimestamp() + ResponseSpinTicks };

            public void Pause()
            {
                if (_spinEnd != 0 && Stopwatch.GetTimestamp() < _spinEnd)
                {
                    _spinner.SpinOnce(sleep1Threshold: -1);
                    return;
                }

                _spinEnd = 0;
                Thread.Sleep(ResponsePollMilliseconds);
            }
        }
    }
}
