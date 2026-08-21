using Brovan.Core.Emulation;
using Brovan.Core.Emulation.Guests;
using Brovan.Core;
using Brovan.Analysis;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan
{
    public sealed class GhostPatch
    {
        public ulong Address;
        public uint Size;
        public byte[] Original = Array.Empty<byte>();
        public byte[] Patched = Array.Empty<byte>();
        public IntPtr BlockHookHandle = IntPtr.Zero;
    }

    [Flags]
    public enum MemoryWatchType
    {
        None = 0,
        Read = 1,
        Write = 2,
        Fetch = 4,
        Execute = Fetch,
        Access = Read | Write | Fetch
    }

    public sealed class MemoryWatchpoint
    {
        public int Id;
        public ulong Address;
        public uint Size;
        public MemoryWatchType Type;
        public IntPtr ReadHookHandle = IntPtr.Zero;
        public IntPtr WriteHookHandle = IntPtr.Zero;
        public IntPtr FetchHookHandle = IntPtr.Zero;
    }

    public enum UnknownBinaryLaunchMode
    {
        Windows = 1,
        Linux = 2,
        Generic = 3
    }

    public sealed class CallTraceFrame
    {
        public uint ThreadId;
        public ulong CallAddress;
        public ulong TargetAddress;
        public ulong ReturnAddress;
        public ulong StackPointer;
        public string CallSymbol = string.Empty;
        public string TargetSymbol = string.Empty;
        public string ReturnSymbol = string.Empty;
    }

    public sealed class FuncMon
    {
        public ulong Address;
        public string Name = string.Empty;
        public string Convention = "win64";
        public List<string> ArgTypes = new();
        public IntPtr HookHandle = IntPtr.Zero;
    }

    internal sealed class EmulatorSessionState
    {
        public IcedX86Disassembler Disassembler = null!;
        public BinaryFile Binary = null!;
        public BinaryEmulator Emulator = null!;
        public ulong MappedMainModuleBase;
        public BinaryArchitecture Arch;
        public EmulatorSnapshot Snapshot = null!;
        public bool HidePrefix;
        public bool Debug;
        public bool IsQuickMode;
    }

    internal sealed class DebuggerState
    {
        public readonly HashSet<ulong> Breakpoints = new();
        public readonly Dictionary<ulong, string> ConditionalBreakpoints = new();
        public IntPtr BreakpointHookHandle = IntPtr.Zero;
        public readonly Dictionary<int, MemoryWatchpoint> Watchpoints = new();
        public int NextWatchpointId = 1;
        public bool Paused;
        public bool PauseRequested;
        // Read from the app's debugger views on another thread, which must never see a stale false.
        public volatile bool GuestExecuting;
        public readonly Dictionary<uint, EmulatedThreadState> PausedThreadStates = new();
        public readonly Dictionary<uint, int> PausedThreadExitCodes = new();
        public readonly List<int> PausedThreadOrder = new();
        public bool BreakpointsSuppressed;
        public bool SkipBreakpointOnce;
        public ulong SkipBreakpointAddress;
        public int SkipBreakpointThreadId;
        public bool StopDisplayActive;
        public int StopDisplayTop;
        public int StopDisplayHeight;
        public int StopDisplayReservedHeight;
        public int PendingStopDisplayTop = -1;
        public int PromptTop = -1;
        public readonly HashSet<int> DirtyRows = new();
        public readonly List<string> CommandHistory = new();
    }

    internal sealed class HookState
    {
        public CodeHookCallback InstructionHook = null!;
        public CodeHookCallback BreakpointHook = null!;
        public CodeHookCallback StepHookDelegate = null!;
        public MemoryHookCallback MemoryHook = null!;
        public CodeHookCallback GhostCodeHook = null!;
        public MemoryHookCallback WatchMemoryHook = null!;
        public IntPtr InstructionHookHandle = IntPtr.Zero;
        public IntPtr TempStepHookHandle = IntPtr.Zero;
        public ulong TempStepTarget;
        public IntPtr GeneralMemoryHookHandle = IntPtr.Zero;
    }

    internal sealed class TraceState
    {
        public bool LdrpLogEnabled;
        public ulong LdrpLogInternalAddress;
        public CodeHookCallback LdrpLogHook = null!;
        public IntPtr LdrpLogHookHandle = IntPtr.Zero;

        public readonly Dictionary<ulong, FuncMon> FuncMons = new();
        public readonly Dictionary<ulong, Stack<ulong>> FuncMonPendingReturns = new();
        public readonly Dictionary<ulong, IntPtr> FuncMonReturnHooks = new();
        public CodeHookCallback FuncMonEntryHook = null!;
        public CodeHookCallback FuncMonReturnHook = null!;

        public bool CallTraceEnabled;
        public string CallTraceLastError = string.Empty;
        public int CallTraceMaxDepth = 128;
        public CodeHookCallback CallTraceHook = null!;
        public IntPtr CallTraceHookHandle = IntPtr.Zero;
        public readonly Dictionary<uint, List<CallTraceFrame>> CallTraceStacks = new();
    }

    internal sealed class LaunchState
    {
        public UnknownBinaryLaunchMode PendingUnknownLaunchMode = UnknownBinaryLaunchMode.Windows;
        public WindowsBlobLaunchMode PendingWindowsBlobLaunchMode = WindowsBlobLaunchMode.Direct;
        public Arch PendingGenericArch = Core.Emulation.Arch.X86;
        public Mode PendingGenericMode = Mode.MODE_32;
        public ulong PendingGenericLoadAddress = 0x10000000UL;
        public ulong PendingGenericEntryAddress = 0x10000000UL;
        public ulong PendingGenericStackSize = 0x100000UL;
    }

    internal class Variables
    {
        private static readonly EmulatorSessionState Session = new();
        private static readonly DebuggerState Debugger = new();
        private static readonly HookState Hooks = new();
        private static readonly TraceState Trace = new();
        private static readonly LaunchState Launch = new();

        public static IcedX86Disassembler Disassembler { get => Session.Disassembler; set => Session.Disassembler = value; }
        public static BinaryFile Binary { get => Session.Binary; set => Session.Binary = value; }
        public static BinaryEmulator Emulator { get => Session.Emulator; set => Session.Emulator = value; }
        public static ulong MappedMainModuleBase { get => Session.MappedMainModuleBase; set => Session.MappedMainModuleBase = value; }
        public static BinaryArchitecture Arch { get => Session.Arch; set => Session.Arch = value; }
        public static EmulatorSnapshot Snapshot { get => Session.Snapshot; set => Session.Snapshot = value; }
        public static bool HidePrefix { get => Session.HidePrefix; set => Session.HidePrefix = value; }
        public static bool Debug { get => Session.Debug; set => Session.Debug = value; }
        public static bool IsQuickMode { get => Session.IsQuickMode; set => Session.IsQuickMode = value; }

        public static CodeHookCallback InstructionHook { get => Hooks.InstructionHook; set => Hooks.InstructionHook = value; }
        public static CodeHookCallback BpHook { get => Hooks.BreakpointHook; set => Hooks.BreakpointHook = value; }
        public static CodeHookCallback StepHookDelegate { get => Hooks.StepHookDelegate; set => Hooks.StepHookDelegate = value; }
        public static MemoryHookCallback MemoryHook { get => Hooks.MemoryHook; set => Hooks.MemoryHook = value; }
        public static CodeHookCallback GCodeHook { get => Hooks.GhostCodeHook; set => Hooks.GhostCodeHook = value; }
        public static IntPtr InstrHookHandle { get => Hooks.InstructionHookHandle; set => Hooks.InstructionHookHandle = value; }
        public static IntPtr BpHookHandle { get => Debugger.BreakpointHookHandle; set => Debugger.BreakpointHookHandle = value; }
        public static bool GPatch { get; set; }
        public static MemoryHookCallback WatchMemoryHook { get => Hooks.WatchMemoryHook; set => Hooks.WatchMemoryHook = value; }
        public static IntPtr GeneralMemoryHookHandle { get => Hooks.GeneralMemoryHookHandle; set => Hooks.GeneralMemoryHookHandle = value; }
        public static IntPtr TempStepHookHandle { get => Hooks.TempStepHookHandle; set => Hooks.TempStepHookHandle = value; }
        public static ulong TempStepTarget { get => Hooks.TempStepTarget; set => Hooks.TempStepTarget = value; }

        public static bool ShowInstrsFilterEnabled = false;
        public static readonly HashSet<string> ShowInstrsModuleFilter = new(StringComparer.OrdinalIgnoreCase);
        public static readonly List<(ulong Start, ulong End)> ShowInstrsRanges = new();

        public static HashSet<ulong> Breakpoints => Debugger.Breakpoints;
        public static Dictionary<ulong, string> ConditionalBreakpoints => Debugger.ConditionalBreakpoints;
        public static Dictionary<int, MemoryWatchpoint> Watchpoints => Debugger.Watchpoints;
        public static int NextWatchpointId { get => Debugger.NextWatchpointId; set => Debugger.NextWatchpointId = value; }
        public static bool DebuggerPaused { get => Debugger.Paused; set => Debugger.Paused = value; }
        public static bool DebuggerPauseRequested { get => Debugger.PauseRequested; set => Debugger.PauseRequested = value; }
        public static bool GuestExecuting { get => Debugger.GuestExecuting; set => Debugger.GuestExecuting = value; }
        public static Dictionary<uint, EmulatedThreadState> DebuggerPausedThreadStates => Debugger.PausedThreadStates;
        public static Dictionary<uint, int> DebuggerPausedThreadExitCodes => Debugger.PausedThreadExitCodes;
        public static List<int> DebuggerPausedThreadOrder => Debugger.PausedThreadOrder;
        public static bool BreakpointsSuppressed { get => Debugger.BreakpointsSuppressed; set => Debugger.BreakpointsSuppressed = value; }
        public static bool SkipBreakpointOnce { get => Debugger.SkipBreakpointOnce; set => Debugger.SkipBreakpointOnce = value; }
        public static ulong SkipBreakpointAddress { get => Debugger.SkipBreakpointAddress; set => Debugger.SkipBreakpointAddress = value; }
        public static int SkipBreakpointThreadId { get => Debugger.SkipBreakpointThreadId; set => Debugger.SkipBreakpointThreadId = value; }
        public static bool DebuggerStopDisplayActive { get => Debugger.StopDisplayActive; set => Debugger.StopDisplayActive = value; }
        public static int DebuggerStopDisplayTop { get => Debugger.StopDisplayTop; set => Debugger.StopDisplayTop = value; }
        public static int DebuggerStopDisplayHeight { get => Debugger.StopDisplayHeight; set => Debugger.StopDisplayHeight = value; }
        public static int DebuggerStopDisplayReservedHeight { get => Debugger.StopDisplayReservedHeight; set => Debugger.StopDisplayReservedHeight = value; }
        public static int DebuggerPendingStopDisplayTop { get => Debugger.PendingStopDisplayTop; set => Debugger.PendingStopDisplayTop = value; }
        public static int DebuggerPromptTop { get => Debugger.PromptTop; set => Debugger.PromptTop = value; }
        public static HashSet<int> DebuggerDirtyRows => Debugger.DirtyRows;
        public static List<string> DebuggerCommandHistory => Debugger.CommandHistory;

        public static readonly List<GhostPatch> GhostPatches = new();

        public static bool LdrpLogEnabled { get => Trace.LdrpLogEnabled; set => Trace.LdrpLogEnabled = value; }
        public static ulong LdrpLogInternalAddress { get => Trace.LdrpLogInternalAddress; set => Trace.LdrpLogInternalAddress = value; }
        public static CodeHookCallback LdrpLogHook { get => Trace.LdrpLogHook; set => Trace.LdrpLogHook = value; }
        public static IntPtr LdrpLogHookHandle { get => Trace.LdrpLogHookHandle; set => Trace.LdrpLogHookHandle = value; }
        public static Dictionary<ulong, FuncMon> FuncMons => Trace.FuncMons;
        public static Dictionary<ulong, Stack<ulong>> FuncMonPendingReturns => Trace.FuncMonPendingReturns;
        public static Dictionary<ulong, IntPtr> FuncMonReturnHooks => Trace.FuncMonReturnHooks;
        public static CodeHookCallback FuncMonEntryHook { get => Trace.FuncMonEntryHook; set => Trace.FuncMonEntryHook = value; }
        public static CodeHookCallback FuncMonReturnHook { get => Trace.FuncMonReturnHook; set => Trace.FuncMonReturnHook = value; }
        public static bool CallTraceEnabled { get => Trace.CallTraceEnabled; set => Trace.CallTraceEnabled = value; }
        public static string CallTraceLastError { get => Trace.CallTraceLastError; set => Trace.CallTraceLastError = value; }
        public static int CallTraceMaxDepth { get => Trace.CallTraceMaxDepth; set => Trace.CallTraceMaxDepth = value; }
        public static CodeHookCallback CallTraceHook { get => Trace.CallTraceHook; set => Trace.CallTraceHook = value; }
        public static IntPtr CallTraceHookHandle { get => Trace.CallTraceHookHandle; set => Trace.CallTraceHookHandle = value; }
        public static Dictionary<uint, List<CallTraceFrame>> CallTraceStacks => Trace.CallTraceStacks;

        public static UnknownBinaryLaunchMode PendingUnknownLaunchMode { get => Launch.PendingUnknownLaunchMode; set => Launch.PendingUnknownLaunchMode = value; }
        public static WindowsBlobLaunchMode PendingWindowsBlobLaunchMode { get => Launch.PendingWindowsBlobLaunchMode; set => Launch.PendingWindowsBlobLaunchMode = value; }
        public static Arch PendingGenericArch { get => Launch.PendingGenericArch; set => Launch.PendingGenericArch = value; }
        public static Mode PendingGenericMode { get => Launch.PendingGenericMode; set => Launch.PendingGenericMode = value; }
        public static ulong PendingGenericLoadAddress { get => Launch.PendingGenericLoadAddress; set => Launch.PendingGenericLoadAddress = value; }
        public static ulong PendingGenericEntryAddress { get => Launch.PendingGenericEntryAddress; set => Launch.PendingGenericEntryAddress = value; }
        public static ulong PendingGenericStackSize { get => Launch.PendingGenericStackSize; set => Launch.PendingGenericStackSize = value; }
    }
}
