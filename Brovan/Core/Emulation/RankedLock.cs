using System.Diagnostics;
using System.Text;
using Brovan.Core.Helpers;
using StatsSlot = Brovan.Core.Helpers.StatsSlots.Slot;

namespace Brovan.Core.Emulation
{
    public sealed class RankedLock : IDisposable
    {
        // Guest domain locks take ranks 2 to 10, between Big and Core's address space (11) and scheduler lock (12).
        internal const int BigRank = 1;
        internal const int DeviceRank = 2;
        internal const int FileObjectRank = 9;
        internal const int AddressSpaceRank = 11;
        internal const int SchedulerRank = 12;
        internal const int BackendMappingRank = 13;

        // A lock of this rank takes no other ranked lock while held.
        internal const int LeafRank = 14;

        internal static readonly bool OrderChecked = Environment.GetEnvironmentVariable("BROVAN_LOCK_ORDER") == "1";

        private static readonly bool RecordsHeld = OrderChecked || Environment.GetEnvironmentVariable("BROVAN_LOCK_STATS") == "1";

        private const int MaxHeld = LeafRank;

        private sealed class HeldRecord
        {
            public readonly RankedLock?[] Locks = new RankedLock?[MaxHeld];
            public readonly int[] Depths = new int[MaxHeld];
            public int Count;

            public int IndexOf(RankedLock Lock)
            {
                for (int i = Count - 1; i >= 0; i--)
                {
                    if (ReferenceEquals(Locks[i], Lock))
                        return i;
                }
                return -1;
            }

            public void RemoveAt(int Index)
            {
                Count--;
                for (int i = Index; i < Count; i++)
                {
                    Locks[i] = Locks[i + 1];
                    Depths[i] = Depths[i + 1];
                }
                Locks[Count] = null;
                Depths[Count] = 0;
            }
        }

        [ThreadStatic]
        private static HeldRecord? t_record;

        private const int Acquires = 0;
        private const int WaitTicks = 1;
        private const int HoldTicks = 2;
        private const int IdleTicks = 3;
        private const int HeldSince = 4;
        private const int Releases = 5;
        private const int CallBase = 8;
        private const int CallCount = 0;
        private const int CallHeld = 1;
        private const int CallMax = 2;
        private const int CallFields = 3;
        private const int CallNumbers = 0x2000;
        private const int SiteNumbers = 8;
        private const int SiteBase = CallBase + CallNumbers * CallFields;
        private const int ReportedCalls = 12;
        private const int ReportInterval = 1 << 16;

        private readonly object _monitor = new();
        private readonly PeriodicStats _stats;
        private readonly string[] _callNames;
        private readonly string[] _siteNames;
        private readonly long _created = Stopwatch.GetTimestamp();
        private StatsSlots _slots;
        private long _lastReport;

        internal readonly string Name;
        internal readonly int Rank;
        private readonly BinaryEmulator _gate;

        internal RankedLock(string Name, int Rank, BinaryEmulator Gate = null, bool CountsCalls = false)
        {
            this.Name = Name;
            this.Rank = Rank;
            _gate = Gate;
            _lastReport = _created;
            _stats = new PeriodicStats("BROVAN_LOCK_STATS", $"Lock {Name}:", Describe, ReportInterval);
            if (!_stats.Enabled)
                return;

            _slots = new StatsSlots(CountsCalls ? SiteBase + SiteNumbers * CallFields : CallBase);
            if (!CountsCalls)
                return;

            _callNames = new string[CallNumbers];
            _siteNames = new string[SiteNumbers];
        }

        // One lock per object of a kind, such as a file object. It shares the kind's name, rank and stats, and a
        // thread may not hold two of one kind.
        internal RankedLock(RankedLock Kind)
        {
            Name = Kind.Name;
            Rank = Kind.Rank;
            _gate = Kind._gate;
            _stats = Kind._stats;
            _slots = Kind._slots;
        }

        internal bool IsHeld => Monitor.IsEntered(_monitor);

        private bool Skipped => _gate != null && !_gate.SmpEnabled;

        internal bool CountsHolds => _callNames != null && _slots != null;

        // A gated lock is taken only through EnterScope, which remembers whether it took the monitor.
        internal void Enter()
        {
            if (_gate != null)
                throw new InvalidOperationException($"{Name} is taken only through EnterScope.");
            EnterMonitor();
        }

        private void EnterMonitor()
        {
            if (!RecordsHeld)
            {
                Monitor.Enter(_monitor);
                return;
            }

            HeldRecord Record = t_record ??= new HeldRecord();
            int Index = Record.IndexOf(this);
            if (Index >= 0)
            {
                Monitor.Enter(_monitor);
                Record.Depths[Index]++;
                return;
            }

            if (OrderChecked)
                CheckOrder(Record);

            StatsSlots Slots = _slots;
            long Start = Slots != null ? Stopwatch.GetTimestamp() : 0;
            Monitor.Enter(_monitor);
            Push(Record);
            if (Slots != null)
                NoteFirstTake(Slots, Start);
        }

        internal bool TryEnter()
        {
            if (_gate != null)
                throw new InvalidOperationException($"{Name} is taken only through EnterScope.");
            if (!RecordsHeld)
                return Monitor.TryEnter(_monitor);

            HeldRecord Record = t_record ??= new HeldRecord();
            int Index = Record.IndexOf(this);
            if (Index >= 0)
            {
                if (!Monitor.TryEnter(_monitor))
                    return false;
                Record.Depths[Index]++;
                return true;
            }

            if (OrderChecked)
                CheckOrder(Record);

            StatsSlots Slots = _slots;
            long Start = Slots != null ? Stopwatch.GetTimestamp() : 0;
            if (!Monitor.TryEnter(_monitor))
                return false;

            Push(Record);
            if (Slots != null)
                NoteFirstTake(Slots, Start);
            return true;
        }

        private void Push(HeldRecord Record)
        {
            if (Record.Count == MaxHeld)
                FailOrder($"{Name} taken while {MaxHeld} ranked locks are held.");

            Record.Locks[Record.Count] = this;
            Record.Depths[Record.Count] = 1;
            Record.Count++;
        }

        internal void Exit()
        {
            if (!RecordsHeld)
            {
                Monitor.Exit(_monitor);
                return;
            }

            HeldRecord? Record = t_record;
            int Index = Record != null ? Record.IndexOf(this) : -1;
            bool Released = Index >= 0 && --Record!.Depths[Index] == 0;
            if (Released)
                Record!.RemoveAt(Index);

            StatsSlots Slots = _slots;
            if (Slots == null || !Released)
            {
                Monitor.Exit(_monitor);
                return;
            }

            long[] S = Slots.Current.Values;
            S[HoldTicks] += Stopwatch.GetTimestamp() - S[HeldSince];
            Monitor.Exit(_monitor);
            _stats.TickSlot(ref S[Releases]);
        }

        [System.Runtime.CompilerServices.InlineArray(MaxHeld)]
        internal struct LockSlots
        {
            private RankedLock? _first;
        }

        internal readonly struct LeftLocks
        {
            private readonly LockSlots _locks;
            private readonly int _count;

            internal LeftLocks(LockSlots Locks, int Count)
            {
                _locks = Locks;
                _count = Count;
            }

            internal bool Any => _count != 0;

            internal void Restore()
            {
                LockSlots Order = _locks;
                for (int i = 1; i < _count; i++)
                {
                    RankedLock Lock = Order[i]!;
                    int j = i - 1;
                    for (; j >= 0 && Order[j]!.Rank > Lock.Rank; j--)
                        Order[j + 1] = Order[j];
                    Order[j + 1] = Lock;
                }

                for (int i = 0; i < _count; i++)
                    Order[i]!.EnterMonitor();
            }
        }

        // Leaves nothing when one of the locks is held more than once, because a caller further out counts on it.
        internal static LeftLocks TryLeaveAll(ReadOnlySpan<RankedLock> Locks)
        {
            LockSlots Left = default;
            int Count = 0;
            return LeaveHeld(Locks, null, ref Left, ref Count) ? new LeftLocks(Left, Count) : default;
        }

        // Restore takes the left locks again, so a lock outside them that stays held would come before them.
        private static void CheckLeavesAllHeld(ReadOnlySpan<RankedLock> Locks)
        {
            if (t_record is not HeldRecord Record)
                return;

            for (int i = 0; i < Record.Count; i++)
            {
                RankedLock Held = Record.Locks[i]!;
                bool Leaving = false;
                foreach (RankedLock Lock in Locks)
                    Leaving |= ReferenceEquals(Lock, Held);

                if (!Leaving)
                    FailOrder($"{Held.Name} is held while the locks around it are left.");
            }
        }

        // A lock held more than once stays held. Without a wait the whole leave is undone.
        private static bool LeaveHeld(ReadOnlySpan<RankedLock> Locks, RankedLock? Waiting, ref LockSlots Left, ref int Count)
        {
            if (OrderChecked)
                CheckLeavesAllHeld(Locks);

            for (int i = Locks.Length - 1; i >= 0; i--)
            {
                RankedLock Lock = Locks[i];
                if (ReferenceEquals(Lock, Waiting) || !Lock.IsHeld)
                    continue;

                Lock.Exit();
                if (Lock.IsHeld)
                {
                    Lock.EnterMonitor();
                    if (Waiting == null)
                    {
                        new LeftLocks(Left, Count).Restore();
                        Count = 0;
                        return false;
                    }

                    if (OrderChecked)
                        FailOrder($"{Lock.Name} is held more than once around a wait on {Waiting.Name}.");
                    continue;
                }

                Left[Count++] = Lock;
            }

            return true;
        }

        internal Scope EnterScope()
        {
            if (Skipped)
                return default;

            EnterMonitor();
            return new Scope(this);
        }

        private void CheckOrder(HeldRecord Record)
        {
            for (int i = 0; i < Record.Count; i++)
            {
                RankedLock Other = Record.Locks[i]!;
                if (Other.Rank >= Rank)
                    FailOrder($"{Name} (rank {Rank}) taken while {Other.Name} (rank {Other.Rank}) is held.");
            }
        }

        internal void AssertHeld(string Where)
        {
            if (OrderChecked && !Skipped && !IsHeld)
                FailOrder($"{Where} runs without {Name}.");
        }

        // A path that takes a lock of this rank only on a rare branch is checked on every run.
        internal static void AssertMayTake(int Rank, string Where)
        {
            if (!OrderChecked || t_record is not HeldRecord Record)
                return;

            for (int i = 0; i < Record.Count; i++)
            {
                RankedLock Held = Record.Locks[i]!;
                if (Held.Rank >= Rank)
                    FailOrder($"{Where} can take a rank {Rank} lock while {Held.Name} (rank {Held.Rank}) is held.");
            }
        }

        internal static void AssertNoneHeld(string Where)
        {
            if (OrderChecked && t_record is HeldRecord Record && Record.Count != 0)
                FailOrder($"{Where} runs while {Record.Locks[0]!.Name} is held.");
        }

        internal static void AssertOneHeld(RankedLock First, RankedLock Second, string Where)
        {
            if (!OrderChecked || First.Skipped || First.IsHeld || Second.Skipped || Second.IsHeld)
                return;

            FailOrder($"{Where} runs without {First.Name} or {Second.Name}.");
        }

        // A lock order fault is a bug in Brovan, and no handler may catch it.
        internal static void FailOrder(string Message)
        {
            Utils.LogError($"[RankedLock] {Message}");
            Environment.FailFast($"[RankedLock] {Message}");
        }

        internal bool Wait(int Milliseconds)
        {
            if (Skipped)
                return false;

            StatsSlots Slots = _slots;
            if (Slots == null)
                return Monitor.Wait(_monitor, Milliseconds);

            long[] S = Slots.Current.Values;
            long Start = Stopwatch.GetTimestamp();
            S[HoldTicks] += Start - S[HeldSince];
            bool Signalled = Monitor.Wait(_monitor, Milliseconds);
            long Now = Stopwatch.GetTimestamp();
            S[IdleTicks] += Now - Start;
            S[HeldSince] = Now;
            return Signalled;
        }

        internal void Pulse()
        {
            if (!Skipped)
                Monitor.Pulse(_monitor);
        }

        internal void PulseAll()
        {
            if (!Skipped)
                Monitor.PulseAll(_monitor);
        }

        // The other locks go before the wait and this one inside Monitor.Wait, so no pulse falls between.
        internal bool WaitLeavingOthers(ReadOnlySpan<RankedLock> Locks, int Milliseconds)
        {
            if (Skipped)
                return false;

            if (OrderChecked)
            {
                HeldRecord? Record = t_record;
                int Index = Record?.IndexOf(this) ?? -1;
                if (Index < 0 || Record!.Depths[Index] != 1)
                    FailOrder($"A wait on {Name} runs without it held exactly once.");
            }

            LockSlots Left = default;
            int Count = 0;
            LeaveHeld(Locks, this, ref Left, ref Count);

            bool Signalled = Wait(Milliseconds);
            if (Count == 0)
                return Signalled;

            Exit();
            Left[Count++] = this;
            new LeftLocks(Left, Count).Restore();
            return Signalled;
        }

        internal long HeldTicks()
        {
            long[] S = _slots.Current.Values;
            HeldRecord? Record = t_record;
            bool Holding = Record != null && Record.IndexOf(this) >= 0;
            return Holding ? S[HoldTicks] + Stopwatch.GetTimestamp() - S[HeldSince] : S[HoldTicks];
        }

        internal void NoteCall(uint Number, string CallName, long HeldBefore)
        {
            int Index = (int)(Number % CallNumbers);
            NoteHold(CallBase + Index * CallFields, HeldBefore);
            _callNames[Index] ??= CallName;
        }

        internal void NoteSite(int Site, string SiteName, long HeldBefore)
        {
            NoteHold(SiteBase + Site * CallFields, HeldBefore);
            _siteNames[Site] ??= SiteName;
        }

        private void NoteHold(int Base, long HeldBefore)
        {
            long Held = HeldTicks() - HeldBefore;
            long[] S = _slots.Current.Values;
            S[Base + CallCount]++;
            S[Base + CallHeld] += Held;
            if (Held > S[Base + CallMax])
                S[Base + CallMax] = Held;
        }

        internal void Report()
        {
            if (_slots != null)
                _stats.Report();
        }

        // Runs after every worker has stopped. A later taker, such as a debugger query, skips the stats.
        public void Dispose()
        {
            StatsSlots Slots = _slots;
            Volatile.Write(ref _slots, null);
            Slots?.Dispose();
        }

        private static void NoteFirstTake(StatsSlots Slots, long Start)
        {
            long[] S = Slots.Current.Values;
            long Now = Stopwatch.GetTimestamp();
            S[Acquires]++;
            S[WaitTicks] += Now - Start;
            S[HeldSince] = Now;
        }

        private static double Milliseconds(long Ticks) => Ticks * 1000.0 / Stopwatch.Frequency;

        // Runs under the report lock of PeriodicStats, so only one thread takes deltas at a time.
        private void Describe(StringBuilder Text)
        {
            StatsSlots Slots = _slots;
            if (Slots == null)
                return;

            long Now = Stopwatch.GetTimestamp();
            long Interval = Math.Max(1, Now - _lastReport);
            _lastReport = Now;
            Text.Append($" {Milliseconds(Interval):F0} ms since the last report, {Milliseconds(Now - _created):F0} ms in all.");

            IList<StatsSlot> All = Slots.All;
            long HoldTotal = 0;
            foreach (StatsSlot Slot in All)
            {
                long Acq = Slot.TakeDelta(Acquires);
                long Wait = Slot.TakeDelta(WaitTicks);
                long Hold = Slot.TakeDelta(HoldTicks);
                long Idle = Slot.TakeDelta(IdleTicks);
                HoldTotal += Hold;
                if (Acq == 0 && Idle == 0)
                    continue;

                Text.Append($" [{Slot.Thread}: {Acq} takes, wait {(double)Wait / Interval:F2}, hold {(double)Hold / Interval:F2}, asleep {(double)Idle / Interval:F2} cores]");
            }

            if (_callNames != null)
                DescribeCalls(Text, All, HoldTotal, Interval);
        }

        private void DescribeCalls(StringBuilder Text, IList<StatsSlot> All, long HoldTotal, long Interval)
        {
            long[] Count = new long[CallNumbers];
            long[] Held = new long[CallNumbers];
            long[] Max = new long[CallNumbers];
            foreach (StatsSlot Slot in All)
            {
                for (int i = 0; i < CallNumbers; i++)
                {
                    int Base = CallBase + i * CallFields;
                    Count[i] += Slot.TakeDelta(Base + CallCount);
                    Held[i] += Slot.TakeDelta(Base + CallHeld);
                    Max[i] = Math.Max(Max[i], Volatile.Read(ref Slot.Values[Base + CallMax]));
                }
            }

            long HandlerHold = 0;
            for (int i = 0; i < CallNumbers; i++)
                HandlerHold += Held[i];

            Text.Append($" Handlers held it {(double)HandlerHold / Interval:F2} cores, the rest {(double)(HoldTotal - HandlerHold) / Interval:F2} cores.");

            int[] Order = new int[CallNumbers];
            for (int i = 0; i < CallNumbers; i++)
                Order[i] = i;
            Array.Sort((long[])Held.Clone(), Order);
            for (int k = 0, Shown = 0; k < CallNumbers && Shown < ReportedCalls; k++)
            {
                int i = Order[CallNumbers - 1 - k];
                if (Count[i] == 0)
                    break;

                Shown++;
                Text.Append($" {_callNames[i] ?? $"0x{i:X}"} {Count[i]} calls, {Milliseconds(Held[i]):F1} ms, longest since start {Milliseconds(Max[i]) * 1000:F0} us;");
            }

            Text.Append(" Sites:");
            for (int Site = 0; Site < SiteNumbers; Site++)
            {
                int Base = SiteBase + Site * CallFields;
                long SiteCount = 0, SiteHeld = 0, SiteMax = 0;
                foreach (StatsSlot Slot in All)
                {
                    SiteCount += Slot.TakeDelta(Base + CallCount);
                    SiteHeld += Slot.TakeDelta(Base + CallHeld);
                    SiteMax = Math.Max(SiteMax, Volatile.Read(ref Slot.Values[Base + CallMax]));
                }

                if (SiteCount != 0)
                    Text.Append($" {_siteNames[Site]} {SiteCount} times, {(double)SiteHeld / Interval:F2} cores, longest since start {Milliseconds(SiteMax) * 1000:F0} us;");
            }
        }

        internal readonly ref struct Scope
        {
            private readonly RankedLock _lock;

            internal Scope(RankedLock Lock) => _lock = Lock;

            public void Dispose() => _lock?.Exit();
        }
    }
}
