using System;
using System.Collections.Generic;
using System.Linq;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Emulation.OS.Linux;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation
{
    public enum SyscallAction { Allow, Deny, ModifyArgs, CallHandler, LogOnly }

    public class SyscallContext
    {
        public uint Number;
        public string Name;
        public ulong[] Args;
        public ulong ReturnValue;
        public BinaryEmulator Emulator;
        public bool Handled;
        public bool CancelEmulation;
    }

    public delegate SyscallContext SyscallHandler(SyscallContext ctx);

    public sealed class SyscallHistoryEntry
    {
        public long Sequence { get; set; }
        public DateTime TimestampUtc { get; set; }
        public GuestOsKind Guest { get; set; }
        public SyscallAbi Abi { get; set; }
        public uint ThreadId { get; set; }
        public ulong Rip { get; set; }
        public uint Number { get; set; }
        public string Name { get; set; }
        public ulong[] Args { get; set; } = Array.Empty<ulong>();
        public ulong ReturnValue { get; set; }
        public bool Implemented { get; set; }
        public bool HandledByRule { get; set; }
    }

    public class SyscallRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public uint? Number { get; set; }
        public int ArgsCount { get; set; } = 0;
        public string Name { get; set; }
        public SyscallAction Action { get; set; } = SyscallAction.Allow;
        public ulong? ForcedReturn { get; set; }
        public Dictionary<int, ulong> ModifyArgs { get; set; } = new Dictionary<int, ulong>();
        public SyscallHandler Handler { get; set; }
        public bool Interactive { get; set; }

        public bool Matches(SyscallContext ctx)
        {
            if (Number.HasValue && Number.Value == ctx.Number) return true;
            if (!string.IsNullOrWhiteSpace(Name) && Name.Equals(ctx.Name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }

    public class SyscallManager
    {
        private readonly List<SyscallRule> _rules = new List<SyscallRule>();
        private readonly List<SyscallHistoryEntry> _history = new List<SyscallHistoryEntry>();
        private readonly object _lock = new object();
        private long _nextHistorySequence = 1;
        private bool _traceEnabled;

        public bool TraceEnabled
        {
            get
            {
                return _traceEnabled;
            }
            set
            {
                if (_traceEnabled == value)
                    return;

                _traceEnabled = value;
                if (!value)
                    ClearHistory();
            }
        }

        public int MaxHistoryEntries { get; set; } = 4096;
        public event Action<SyscallContext> OnInteractive;
        private readonly BinaryEmulator _emu;

        public SyscallManager(BinaryEmulator emu)
        {
            _emu = emu;
        }

        public IEnumerable<SyscallRule> ListRules()
        {
            lock (_lock) { return _rules.ToArray(); }
        }

        public SyscallHistoryEntry[] HistorySnapshot()
        {
            if (!TraceEnabled)
                return Array.Empty<SyscallHistoryEntry>();

            lock (_lock)
            {
                return _history.ToArray();
            }
        }

        public void ClearHistory()
        {
            lock (_lock)
            {
                _history.Clear();
                _nextHistorySequence = 1;
            }
        }

        public void RecordSyscall(GuestOsKind guest, SyscallAbi abi, uint number, string name, ulong[] args, ulong returnValue, ulong rip, bool implemented, bool handledByRule = false)
        {
            if (!TraceEnabled)
                return;

            uint ThreadId = 0;
            if (_emu != null)
            {
                if (_emu.CurrentThread != null)
                    ThreadId = _emu.CurrentThread.ThreadId;
                else if (_emu.CurrentThreadId >= 0)
                    ThreadId = (uint)_emu.CurrentThreadId;
            }

            SyscallHistoryEntry Entry = new SyscallHistoryEntry
            {
                Guest = guest,
                Abi = abi,
                ThreadId = ThreadId,
                Rip = rip,
                Number = number,
                Name = name,
                Args = args == null ? Array.Empty<ulong>() : args.ToArray(),
                ReturnValue = returnValue,
                Implemented = implemented,
                HandledByRule = handledByRule,
                TimestampUtc = DateTime.UtcNow
            };

            lock (_lock)
            {
                if (!TraceEnabled)
                    return;

                Entry.Sequence = _nextHistorySequence++;
                _history.Add(Entry);

                int MaxEntries = MaxHistoryEntries <= 0 ? 4096 : MaxHistoryEntries;
                if (_history.Count > MaxEntries)
                    _history.RemoveRange(0, _history.Count - MaxEntries);
            }
        }

        public void AddRule(SyscallRule r)
        {
            lock (_lock) { _rules.Add(r); }
        }

        public bool RemoveRule(string idOrName)
        {
            lock (_lock)
            {
                int removed = _rules.RemoveAll(x => x.Id == idOrName || x.Name?.Equals(idOrName, StringComparison.OrdinalIgnoreCase) == true);
                return removed > 0;
            }
        }

        public SyscallContext HandleSyscall(uint number, string name, ulong[] args)
        {
            var ctx = new SyscallContext { Number = number, Name = name, Args = args, Emulator = _emu };

            if (TraceEnabled)
                _emu.TriggerEventMessage($"[SYSCALL TRACE] {name ?? "sys_" + number.ToString("X")} (0x{number:X}) args: {string.Join(", ", args.Select(a => $"0x{a:X}"))}", LogFlags.General);

            SyscallRule matched = null;
            lock (_lock)
            {
                foreach (var r in _rules)
                {
                    if (r.Matches(ctx)) { matched = r; break; }
                }
            }

            if (matched != null)
            {
                if (matched.Interactive)
                {
                    _emu._emulator.StopEmulation();
                    OnInteractive?.Invoke(ctx);
                    if (ctx.CancelEmulation)
                        _emu._emulator.StopEmulation();
                    if (ctx.Handled) return ctx;
                }

                switch (matched.Action)
                {
                    case SyscallAction.Deny:
                        ctx.ReturnValue = matched.ForcedReturn ?? (ulong)(uint)NTSTATUS.STATUS_ACCESS_DENIED;
                        ctx.Handled = true;
                        return ctx;
                    case SyscallAction.ModifyArgs:
                        foreach (var kv in matched.ModifyArgs)
                            if (kv.Key >= 0 && kv.Key < ctx.Args.Length) ctx.Args[kv.Key] = kv.Value;
                        break;
                    case SyscallAction.CallHandler:
                        if (matched.Handler != null)
                        {
                            var outCtx = matched.Handler(ctx);
                            if (outCtx != null && outCtx.CancelEmulation)
                                _emu._emulator.StopEmulation();
                            if (outCtx != null && outCtx.Handled) return outCtx;
                        }
                        break;
                }
            }

            if (ctx.CancelEmulation)
                _emu._emulator.StopEmulation();

            return ctx;
        }
    }
}