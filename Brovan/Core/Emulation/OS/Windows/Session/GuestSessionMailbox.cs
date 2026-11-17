using System.Diagnostics;
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
        ReceiveHandle = 9,
    }

    internal enum MailboxOutcome
    {
        Answered,
        TooLarge,
        Unavailable,
        TimedOut,
        TargetGone,
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

        private const int TargetSize = LaneCount * LaneSize;

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

        internal const int ResponseTimeoutMilliseconds = 5000;
        private const int SettleLockAttempts = 5;

        private static SessionMapping? _mapping;
        private static bool _unavailable;

        private static readonly uint[] _handledSequences = new uint[LaneCount];
        private static int _nextLane;
        private static int _activeLane = -1;

        internal enum Claim
        {
            Claimed,
            Busy,
            Unavailable,
            TooLarge,
        }

        internal static Claim TryPost(int Slot, SessionOperation Operation, ulong Address, ulong Argument, ReadOnlySpan<byte> Input, int OutputLength,
            out uint Sequence)
        {
            Sequence = 0;
            if (Input.Length > MaxPayloadBytes || OutputLength > MaxPayloadBytes)
                return Claim.TooLarge;

            return TryClaim(Slot, LaneOffset(TargetOffset(Slot), GuestSession.OwnSlot), Operation, Address, Argument, Input, OutputLength, out Sequence);
        }

        // True once the request ended, also when another sender took over the shared lane.
        internal static bool TryTakeAnswer(int Slot, uint Sequence, Span<byte> Output, out MailboxOutcome Outcome, out NTSTATUS Status,
            out int OutputLength, out ulong Result)
        {
            Outcome = MailboxOutcome.TimedOut;
            Status = NTSTATUS.STATUS_SUCCESS;
            OutputLength = 0;
            Result = 0;

            SessionMapping? Mapping = _mapping;
            if (Mapping == null)
            {
                Outcome = MailboxOutcome.Unavailable;
                return true;
            }

            int Lane = LaneOffset(TargetOffset(Slot), GuestSession.OwnSlot);
            return Mapping.ReadUInt32(Lane + AnswerSequenceOffset) == Sequence &&
                TrySettle(Lane, Sequence, MailboxOutcome.TimedOut, false, Output, out Outcome, out Status, out OutputLength, out Result);
        }

        // An answer that already arrived is still taken. Otherwise the target undoes what it made for the request.
        internal static MailboxOutcome Abandon(int Slot, uint Sequence, MailboxOutcome Reason, Span<byte> Output, out NTSTATUS Status, out int OutputLength,
            out ulong Result)
        {
            TrySettle(LaneOffset(TargetOffset(Slot), GuestSession.OwnSlot), Sequence, Reason, true, Output, out MailboxOutcome Outcome, out Status,
                out OutputLength, out Result);
            return Outcome;
        }

        private static bool TrySettle(int Lane, uint Sequence, MailboxOutcome Abandoned, bool Final, Span<byte> Output, out MailboxOutcome Outcome,
            out NTSTATUS Status, out int OutputLength, out ulong Result)
        {
            Outcome = Abandoned;
            Status = NTSTATUS.STATUS_SUCCESS;
            OutputLength = 0;
            Result = 0;

            using SessionLock Lock = Final ? AcquireToSettle() : GuestSession.Acquire();
            SessionMapping? Mapping = _mapping;
            if (Mapping == null)
                return true;

            // Another sender took over the shared lane after this request sat unanswered for a full timeout.
            if (Mapping.ReadUInt32(Lane + RequestSequenceOffset) != Sequence)
                return true;

            // WriteAnswer publishes its sequence last, so an answer seen without the lock is complete.
            bool Answered = Mapping.ReadUInt32(Lane + AnswerSequenceOffset) == Sequence;
            if (!Lock.Held && !Answered)
                return Final;

            if (!Answered)
            {
                Mapping.WriteUInt32(Lane + ReleasedSequenceOffset, Sequence);
                return true;
            }

            Result = Mapping.ReadUInt64(Lane + ResultOffset);
            OutputLength = (int)Math.Min(Mapping.ReadUInt32(Lane + AnswerLengthOffset), (uint)Output.Length);
            if (OutputLength > 0)
                PayloadSpan(Mapping, Lane).Slice(0, OutputLength).CopyTo(Output);

            Status = (NTSTATUS)Mapping.ReadUInt32(Lane + StatusOffset);
            Mapping.WriteUInt32(Lane + ReleasedSequenceOffset, Sequence);
            Outcome = MailboxOutcome.Answered;
            return true;
        }

        private static Claim TryClaim(int Slot, int Lane, SessionOperation Operation, ulong Address, ulong Argument, ReadOnlySpan<byte> Input,
            int OutputLength, out uint Sequence)
        {
            Sequence = 0;
            using SessionLock Lock = GuestSession.Acquire();
            if (!Lock.Held || !TryOpen())
                return Claim.Unavailable;

            SessionMapping Mapping = _mapping!;
            uint Last = Mapping.ReadUInt32(Lane + RequestSequenceOffset);
            if (!IsLaneFree(Mapping, Lane, Last))
                return Claim.Busy;

            Mapping.WriteUInt32(Lane + OperationOffset, (uint)Operation);
            Mapping.WriteUInt64(Lane + AddressOffset, Address);
            Mapping.WriteUInt64(Lane + ArgumentOffset, Argument);
            Mapping.WriteUInt32(Lane + LengthOffset, (uint)(Operation == SessionOperation.ReadMemory ? OutputLength : Input.Length));

            if (Input.Length > 0)
                Input.CopyTo(PayloadSpan(Mapping, Lane));

            Sequence = Last + 1;
            Mapping.WriteUInt32(Lane + RequestSequenceOffset, Sequence);
            SessionPump.Ring(Slot);
            return Claim.Claimed;
        }

        // An answer nobody read for a whole timeout belongs to a sender that is gone.
        private static bool IsLaneFree(SessionMapping Mapping, int Lane, uint Last)
            => Mapping.ReadUInt32(Lane + AnswerSequenceOffset) == Last
                && (Mapping.ReadUInt32(Lane + ReleasedSequenceOffset) == Last
                    || Environment.TickCount64 - (long)Mapping.ReadUInt64(Lane + AnswerTickOffset) >= ResponseTimeoutMilliseconds);

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
            if (Slot < 0 || _mapping == null)
                return false;

            using SessionLock Lock = GuestSession.Acquire();
            SessionMapping? Mapping = _mapping;
            if (!Lock.Held || Mapping == null)
            {
                SessionPump.Rescan();
                return false;
            }

            int Target = TargetOffset(Slot);
            for (int i = 0; i < LaneCount; i++)
            {
                int Index = (_nextLane + i) % LaneCount;
                int Lane = LaneOffset(Target, Index);
                uint Sequence = Mapping.ReadUInt32(Lane + RequestSequenceOffset);
                if (Sequence == _handledSequences[Index])
                    continue;

                _handledSequences[Index] = Sequence;
                if (Mapping.ReadUInt32(Lane + ReleasedSequenceOffset) == Sequence)
                {
                    WriteAnswer(Mapping, Lane, Sequence, 0, 0, 0);
                    continue;
                }

                Operation = (SessionOperation)Mapping.ReadUInt32(Lane + OperationOffset);
                Address = Mapping.ReadUInt64(Lane + AddressOffset);
                Argument = Mapping.ReadUInt64(Lane + ArgumentOffset);
                Length = (int)Math.Min(Mapping.ReadUInt32(Lane + LengthOffset), (uint)MaxPayloadBytes);
                Payload = PayloadSpan(Mapping, Lane);

                _activeLane = Index;
                _nextLane = (Index + 1) % LaneCount;
                return true;
            }

            return false;
        }

        // False when the sender gave the request up, so the caller undoes what it made.
        internal static bool Complete(NTSTATUS Status, ulong Result, int Length)
        {
            int Slot = GuestSession.OwnSlot;
            if (Slot < 0 || _mapping == null || _activeLane < 0)
                return false;

            using SessionLock Lock = AcquireToSettle();
            SessionMapping? Mapping = _mapping;
            if (!Lock.Held || Mapping == null)
                return false;

            int Sender = _activeLane;
            int Lane = LaneOffset(TargetOffset(Slot), Sender);
            uint Sequence = _handledSequences[Sender];
            _activeLane = -1;

            if (Mapping.ReadUInt32(Lane + RequestSequenceOffset) != Sequence)
                return false;

            WriteAnswer(Mapping, Lane, Sequence, Status, Result, Length);
            bool Taken = Mapping.ReadUInt32(Lane + ReleasedSequenceOffset) != Sequence;
            if (Taken && Sender < GuestSession.SlotCount)
                SessionPump.Ring(Sender);

            return Taken;
        }

        // Without the lock the two sides of a request can disagree about its outcome.
        private static SessionLock AcquireToSettle()
        {
            for (int Attempt = 0; Attempt < SettleLockAttempts; Attempt++)
            {
                SessionLock Lock = GuestSession.Acquire();
                if (Lock.Held)
                    return Lock;
            }

            Utils.LogError("[GuestSessionMailbox] The session lock stayed taken, so a request ends without a recorded outcome.");
            return default;
        }

        private static void WriteAnswer(SessionMapping Mapping, int Lane, uint Sequence, NTSTATUS Status, ulong Result, int Length)
        {
            Mapping.WriteUInt32(Lane + AnswerLengthOffset, (uint)Math.Min(Length, MaxPayloadBytes));
            Mapping.WriteUInt64(Lane + ResultOffset, Result);
            Mapping.WriteUInt32(Lane + StatusOffset, (uint)Status);
            Mapping.WriteUInt64(Lane + AnswerTickOffset, (ulong)Environment.TickCount64);
            Mapping.WriteUInt32(Lane + AnswerSequenceOffset, Sequence);
        }

        /// <summary>
        /// A reused slot keeps its previous owner's sequence numbers and unread answers. The caller holds the session lock.
        /// </summary>
        internal static unsafe void Reset(int Slot)
        {
            if (!TryOpen())
                return;

            SessionMapping Mapping = _mapping!;
            int Target = TargetOffset(Slot);
            for (int Index = 0; Index < LaneCount; Index++)
                new Span<byte>(Mapping.Base + LaneOffset(Target, Index), LaneHeaderSize).Clear();

            for (int Other = 0; Other < GuestSession.SlotCount; Other++)
            {
                if (Other == Slot)
                    continue;

                int Lane = LaneOffset(TargetOffset(Other), Slot);
                Mapping.WriteUInt32(Lane + ReleasedSequenceOffset, Mapping.ReadUInt32(Lane + RequestSequenceOffset));
            }

            Array.Clear(_handledSequences);
            _nextLane = 0;
            _activeLane = -1;
        }

        internal static void Close()
        {
            SessionMapping? Mapping = _mapping;
            _mapping = null;
            Mapping?.Dispose();
        }

        private static bool TryOpen()
        {
            if (_mapping != null)
                return true;

            if (_unavailable)
                return false;

            try
            {
                System.IO.Directory.CreateDirectory(GuestSession.Directory);
            }
            catch (Exception Error) when (Error is IOException || Error is UnauthorizedAccessException)
            {
                Utils.LogError($"[GuestSessionMailbox] Unavailable: {Error.Message}");
                _unavailable = true;
                return false;
            }

            _mapping = SessionMapping.OpenFile(Path.Combine(GuestSession.Directory, FileName), FileMode.OpenOrCreate, (long)GuestSession.SlotCount * TargetSize);
            if (_mapping == null)
                _unavailable = true;

            return _mapping != null;
        }

        private static unsafe Span<byte> PayloadSpan(SessionMapping Mapping, int Lane) => new(Mapping.Base + Lane + LaneHeaderSize, MaxPayloadBytes);

        private static int TargetOffset(int Slot) => Slot * TargetSize;

        private static int LaneOffset(int Target, int Sender)
            => Target + (Sender >= 0 ? Sender : SharedLane) * LaneSize;
    }
}
