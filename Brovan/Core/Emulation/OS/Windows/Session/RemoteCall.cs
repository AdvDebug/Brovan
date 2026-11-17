using System.Diagnostics;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal abstract class RemoteCall : ParkedIoRequest
    {
        internal readonly RemoteGuestProcess Target;
        internal readonly SessionOperation Operation;
        internal readonly ulong Address;
        internal readonly ulong Argument;
        internal readonly byte[] Input;
        internal readonly byte[] Output;

        internal long Deadline;
        internal int Slot = -1;
        internal uint Sequence;
        internal bool Posted;

        protected RemoteCall(RemoteGuestProcess Target, SessionOperation Operation, ulong Address, ulong Argument, byte[] Input, int OutputBytes)
        {
            this.Target = Target;
            this.Operation = Operation;
            this.Address = Address;
            this.Argument = Argument;
            this.Input = Input;
            Output = OutputBytes == 0 ? Array.Empty<byte>() : new byte[OutputBytes];
        }

        internal override WinFile File => null;

        internal override string WaitLabel => "remote-call";

        internal virtual NTSTATUS ExitedStatus => NTSTATUS.STATUS_INVALID_CID;

        // A target that only looks gone, because the session lock was not taken, is not reported as exited.
        internal NTSTATUS StatusOf(MailboxOutcome Outcome, NTSTATUS Answered)
            => Outcome == MailboxOutcome.TargetGone && Target.HasExited ? ExitedStatus : RemoteGuestProcess.StatusOf(Outcome, Answered);

        // Runs under KernelLock when the call ends, also after its thread has ended.
        internal abstract NTSTATUS Ended(BinaryEmulator Instance, MailboxOutcome Outcome, NTSTATUS Status, ulong Result, ReadOnlySpan<byte> Answer);
    }

    internal static class RemoteCalls
    {
        private const int PollMilliseconds = 1;

        // Answers often arrive well within one poll interval, so a synchronous sender spins first.
        private static readonly long SpinTicks = Stopwatch.Frequency / 5000;

        private static readonly List<RemoteCall> Pending = new List<RemoteCall>();

        internal static bool HasPending => Pending.Count != 0;

        internal static NTSTATUS Start(BinaryEmulator Instance, RemoteCall Call)
        {
            // Without a session slot no doorbell wakes a parked thread, so the call runs at once.
            if (GuestSession.OwnSlot < 0)
            {
                if (!GuestSession.TryFindLiveSlot(Call.Target.ProcessId, out int Slot))
                    return Conclude(Instance, Call, MailboxOutcome.TargetGone, NTSTATUS.STATUS_SUCCESS, 0, 0);

                MailboxOutcome Outcome = Send(Instance, Call.Target, Slot, Call.Operation, Call.Address, Call.Argument, Call.Input, Call.Output,
                    out NTSTATUS Status, out int OutputLength, out ulong Result);
                return Conclude(Instance, Call, Outcome, Status, Result, OutputLength);
            }

            Call.Deadline = Environment.TickCount64 + GuestSessionMailbox.ResponseTimeoutMilliseconds;
            Pending.Add(Call);
            Instance.WinHelper.ParkForIoRequest(Call);
            Service(Instance);
            return NTSTATUS.STATUS_PENDING;
        }

        internal static void Service(BinaryEmulator Instance)
        {
            long Now = Environment.TickCount64;
            for (int Index = 0; Index < Pending.Count;)
            {
                RemoteCall Call = Pending[Index];
                if (Advance(Instance, Call, Index, Now))
                    Pending.RemoveAt(Index);
                else
                    Index++;
            }
        }

        internal static MailboxOutcome Send(BinaryEmulator? Instance, RemoteGuestProcess Target, int Slot, SessionOperation Operation, ulong Address,
            ulong Argument, ReadOnlySpan<byte> Input, Span<byte> Output, out NTSTATUS Status, out int OutputLength, out ulong Result)
        {
            Status = NTSTATUS.STATUS_SUCCESS;
            OutputLength = 0;
            Result = 0;

            long Deadline = Environment.TickCount64 + GuestSessionMailbox.ResponseTimeoutMilliseconds;
            Backoff Wait = Backoff.Start();
            uint Sequence;

            while (true)
            {
                // A parked call to the same target holds the lane, so its answer is taken first.
                if (Instance != null)
                    ServiceTarget(Instance, Target);

                GuestSessionMailbox.Claim Claimed = GuestSessionMailbox.TryPost(Slot, Operation, Address, Argument, Input, Output.Length, out Sequence);
                if (Claimed == GuestSessionMailbox.Claim.Claimed)
                    break;
                if (Claimed != GuestSessionMailbox.Claim.Busy)
                    return Refusal(Claimed);
                if (Late(Target, Deadline, Environment.TickCount64) is MailboxOutcome Reason)
                    return Reason;

                Wait.Pause();
            }

            Wait = Backoff.Start();
            MailboxOutcome Outcome;
            while (!TryFinish(Target, Slot, Sequence, Deadline, Environment.TickCount64, Output, out Outcome, out Status, out OutputLength, out Result))
                Wait.Pause();

            return Outcome;
        }

        private static bool TryFinish(RemoteGuestProcess Target, int Slot, uint Sequence, long Deadline, long Now, Span<byte> Output, out MailboxOutcome Outcome,
            out NTSTATUS Status, out int OutputLength, out ulong Result)
        {
            if (GuestSessionMailbox.TryTakeAnswer(Slot, Sequence, Output, out Outcome, out Status, out OutputLength, out Result))
                return true;

            if (Late(Target, Deadline, Now) is not MailboxOutcome Reason)
                return false;

            Outcome = GuestSessionMailbox.Abandon(Slot, Sequence, Reason, Output, out Status, out OutputLength, out Result);
            return true;
        }

        private static MailboxOutcome? Late(RemoteGuestProcess Target, long Deadline, long Now)
        {
            if (Target.HasExited)
                return MailboxOutcome.TargetGone;

            return Now >= Deadline ? MailboxOutcome.TimedOut : null;
        }

        private static MailboxOutcome Refusal(GuestSessionMailbox.Claim Claimed)
            => Claimed == GuestSessionMailbox.Claim.TooLarge ? MailboxOutcome.TooLarge : MailboxOutcome.Unavailable;

        private static void ServiceTarget(BinaryEmulator Instance, RemoteGuestProcess Target)
        {
            long Now = Environment.TickCount64;
            for (int Index = 0; Index < Pending.Count; Index++)
            {
                RemoteCall Call = Pending[Index];
                if (Call.Target.ProcessId != Target.ProcessId || !Call.Posted)
                    continue;

                if (Advance(Instance, Call, Index, Now))
                    Pending.RemoveAt(Index);
                return;
            }
        }

        private static bool Advance(BinaryEmulator Instance, RemoteCall Call, int Index, long Now)
        {
            if (!Call.Posted)
            {
                if (HasEarlierCall(Call.Target, Index))
                    return EndIfLate(Instance, Call, Now);

                if (Call.Slot < 0 && !GuestSession.TryFindLiveSlot(Call.Target.ProcessId, out Call.Slot))
                    return End(Instance, Call, MailboxOutcome.TargetGone);

                GuestSessionMailbox.Claim Claimed = GuestSessionMailbox.TryPost(Call.Slot, Call.Operation, Call.Address, Call.Argument, Call.Input,
                    Call.Output.Length, out Call.Sequence);
                switch (Claimed)
                {
                    case GuestSessionMailbox.Claim.Claimed:
                        Call.Posted = true;
                        return false;
                    case GuestSessionMailbox.Claim.Busy:
                        return EndIfLate(Instance, Call, Now);
                    default:
                        return End(Instance, Call, Refusal(Claimed));
                }
            }

            return TryFinish(Call.Target, Call.Slot, Call.Sequence, Call.Deadline, Now, Call.Output, out MailboxOutcome Outcome, out NTSTATUS Status,
                    out int OutputLength, out ulong Result)
                && End(Instance, Call, Outcome, Status, Result, OutputLength);
        }

        private static bool HasEarlierCall(RemoteGuestProcess Target, int Index)
        {
            for (int Earlier = 0; Earlier < Index; Earlier++)
            {
                if (Pending[Earlier].Target.ProcessId == Target.ProcessId)
                    return true;
            }

            return false;
        }

        private static bool EndIfLate(BinaryEmulator Instance, RemoteCall Call, long Now)
            => Late(Call.Target, Call.Deadline, Now) is MailboxOutcome Reason && End(Instance, Call, Reason);

        private static bool End(BinaryEmulator Instance, RemoteCall Call, MailboxOutcome Outcome)
            => End(Instance, Call, Outcome, NTSTATUS.STATUS_SUCCESS, 0, 0);

        private static bool End(BinaryEmulator Instance, RemoteCall Call, MailboxOutcome Outcome, NTSTATUS Status, ulong Result, int OutputLength)
        {
            Call.Complete(Instance, Conclude(Instance, Call, Outcome, Status, Result, OutputLength));
            return true;
        }

        private static NTSTATUS Conclude(BinaryEmulator Instance, RemoteCall Call, MailboxOutcome Outcome, NTSTATUS Status, ulong Result, int OutputLength)
        {
            try
            {
                return Call.Ended(Instance, Outcome, Status, Result, Call.Output.AsSpan(0, Math.Min(OutputLength, Call.Output.Length)));
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[RemoteCalls] Ending {Call.Operation} failed: {Ex.Message}");
                return NTSTATUS.STATUS_UNSUCCESSFUL;
            }
        }

        internal static void Release(BinaryEmulator Instance)
        {
            while (Pending.Count != 0)
            {
                RemoteCall Call = Pending[Pending.Count - 1];
                Pending.RemoveAt(Pending.Count - 1);

                if (!Call.Posted)
                {
                    End(Instance, Call, MailboxOutcome.Unavailable);
                    continue;
                }

                MailboxOutcome Outcome = GuestSessionMailbox.Abandon(Call.Slot, Call.Sequence, MailboxOutcome.Unavailable, Call.Output, out NTSTATUS Status,
                    out int OutputLength, out ulong Result);
                End(Instance, Call, Outcome, Status, Result, OutputLength);
            }
        }

        private struct Backoff
        {
            private long _spinEnd;
            private SpinWait _spinner;

            public static Backoff Start() => new() { _spinEnd = Stopwatch.GetTimestamp() + SpinTicks };

            public void Pause()
            {
                if (_spinEnd != 0 && Stopwatch.GetTimestamp() < _spinEnd)
                {
                    _spinner.SpinOnce(sleep1Threshold: -1);
                    return;
                }

                _spinEnd = 0;
                Thread.Sleep(PollMilliseconds);
            }
        }
    }
}
